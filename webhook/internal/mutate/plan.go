package mutate

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// planner walks one pod and collects the patch operations it needs, the
// problems that make it unacceptable, and the warnings worth returning. It
// only reads the pod; the patch is built from paths and fresh values, never
// from a mutated copy, so the operations are easy to inspect in a test.
//
// The operations come in an order the patch can be applied in: the
// containers' environment first, by the indices the pod has now, then the
// additions that would shift them (the enrolment init container goes in at
// index 0), then the metadata.
type planner struct {
	cfg    Config
	region string

	ops      []Operation
	problems []string
	warnings []string
	stripped []StrippedEnv
}

func (p *planner) plan(pod *corev1.Pod) {
	p.planPod(pod)
	for i := range pod.Spec.InitContainers {
		p.planEnv(&pod.Spec.InitContainers[i], "/spec/initContainers/"+strconv.Itoa(i))
	}
	for i := range pod.Spec.Containers {
		p.planEnv(&pod.Spec.Containers[i], "/spec/containers/"+strconv.Itoa(i))
	}
	if len(p.problems) > 0 {
		return
	}
	if p.cfg.Enrol == EnrolInit {
		p.planEnrol(pod)
	}
	p.planLabel(pod)
	p.planAnnotations(pod)
}

// planPod refuses what no mode can wire: a pod without a network namespace
// of its own (design 7.1), and one carrying the enrolment container or
// volume the webhook did not inject.
func (p *planner) planPod(pod *corev1.Pod) {
	if pod.Spec.HostNetwork {
		p.problems = append(p.problems,
			"pod uses hostNetwork, which has no network namespace of its own for the credentials listener")
	}
	for _, c := range pod.Spec.InitContainers {
		if c.Name == EnrolContainerName {
			p.problems = append(p.problems,
				fmt.Sprintf("init container %q is reserved for the enrolment the webhook injects", EnrolContainerName))
		}
	}
	for _, v := range pod.Spec.Volumes {
		if v.Name == EnrolVolumeName {
			p.problems = append(p.problems,
				fmt.Sprintf("volume %q is reserved for the enrolment token the webhook injects", EnrolVolumeName))
		}
	}
}

// managedEnv is what every container ends up with.
func (p *planner) managedEnv() []corev1.EnvVar {
	return []corev1.EnvVar{
		{Name: EnvCredentialsURI, Value: p.cfg.CredentialsURI()},
		{Name: EnvRegion, Value: p.region},
	}
}

func (p *planner) planEnv(c *corev1.Container, base string) {
	managed := p.managedEnv()
	wanted := make(map[string]string, len(managed))
	for _, v := range managed {
		wanted[v.Name] = v.Value
	}

	kept := make([]corev1.EnvVar, 0, len(c.Env)+len(managed))
	present := make(map[string]bool, len(managed))
	changed := false
	for _, e := range c.Env {
		want, ours := wanted[e.Name]
		switch {
		case ours && e.ValueFrom == nil && e.Value == want:
			present[e.Name] = true
		case e.Name == EnvRegion:
			// The workload chose its region; only the credentials are ours.
			present[e.Name] = true
		case Conflicts(e.Name):
			if p.cfg.ConflictingEnv == Strip {
				p.stripped = append(p.stripped, StrippedEnv{Container: c.Name, Name: e.Name})
				p.warnings = append(p.warnings,
					fmt.Sprintf("cracha: removed %s from container %q: it conflicts with the injected credentials", e.Name, c.Name))
				changed = true
				continue
			}
			p.problems = append(p.problems,
				fmt.Sprintf("container %q sets %s, which conflicts with the injected credentials", c.Name, e.Name))
		}
		kept = append(kept, e)
	}
	for _, v := range managed {
		if present[v.Name] {
			continue
		}
		kept = append(kept, v)
		changed = true
	}
	if !changed {
		return
	}
	op := "replace"
	if c.Env == nil {
		op = "add"
	}
	p.ops = append(p.ops, Operation{Op: op, Path: base + "/env", Value: kept})
}

// planEnrol adds the init mode's enrolment (design 7.2): the token volume
// and, first among the init containers, the container that presents it.
func (p *planner) planEnrol(pod *corev1.Pod) {
	if pod.Spec.Volumes == nil {
		p.ops = append(p.ops, Operation{Op: "add", Path: "/spec/volumes", Value: []corev1.Volume{enrolVolume()}})
	} else {
		p.ops = append(p.ops, Operation{Op: "add", Path: "/spec/volumes/-", Value: enrolVolume()})
	}
	c := p.enrolContainer()
	if pod.Spec.InitContainers == nil {
		p.ops = append(p.ops, Operation{Op: "add", Path: "/spec/initContainers", Value: []corev1.Container{c}})
	} else {
		p.ops = append(p.ops, Operation{Op: "add", Path: "/spec/initContainers/0", Value: c})
	}
}

// enrolVolume is the projected ServiceAccount token the init container
// authenticates with: for the agent only, as short-lived as the API allows,
// and bound to the pod. It is world-readable within the mount so that the
// non-root init container reads it whatever the pod's own user and fsGroup
// are; nothing but that container mounts it.
func enrolVolume() corev1.Volume {
	expiration := int64(EnrolTokenExpirationSeconds)
	mode := int32(0o444)
	return corev1.Volume{
		Name: EnrolVolumeName,
		VolumeSource: corev1.VolumeSource{
			Projected: &corev1.ProjectedVolumeSource{
				DefaultMode: &mode,
				Sources: []corev1.VolumeProjection{{
					ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
						Audience:          EnrolTokenAudience,
						ExpirationSeconds: &expiration,
						Path:              EnrolTokenFile,
					},
				}},
			},
		},
	}
}

// enrolContainer is the init container: the agent image's `enrol`, told the
// node's address, the enrolment port, how long to try and where the token
// is, under the restricted Pod Security standard so that it never makes a
// pod inadmissible. Its resources are fixed and small, with requests equal
// to limits so that a Guaranteed pod stays Guaranteed.
func (p *planner) enrolContainer() corev1.Container {
	no, yes := false, true
	uid := enrolUID
	resources := corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse("10m"),
		corev1.ResourceMemory: resource.MustParse("16Mi"),
	}
	return corev1.Container{
		Name:  EnrolContainerName,
		Image: p.cfg.AgentImage,
		Args:  []string{EnrolArg},
		Env: []corev1.EnvVar{
			{Name: EnvHostIP, ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.hostIP"},
			}},
			{Name: EnvEnrolPort, Value: strconv.Itoa(p.cfg.EnrolPort)},
			{Name: EnvAgentPort, Value: strconv.Itoa(p.cfg.AgentPort)},
			{Name: EnvEnrolTimeout, Value: p.cfg.EnrolTimeout.String()},
			{Name: EnvEnrolTokenFile, Value: EnrolTokenPath},
		},
		Resources: corev1.ResourceRequirements{Requests: resources, Limits: resources.DeepCopy()},
		VolumeMounts: []corev1.VolumeMount{{
			Name:      EnrolVolumeName,
			MountPath: EnrolTokenDir,
			ReadOnly:  true,
		}},
		// The last log line (what it is waiting for, or the timeout) becomes
		// the termination message, so `kubectl describe pod` says why a pod
		// is held in Init.
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		SecurityContext: &corev1.SecurityContext{
			RunAsNonRoot:             &yes,
			RunAsUser:                &uid,
			RunAsGroup:               &uid,
			AllowPrivilegeEscalation: &no,
			ReadOnlyRootFilesystem:   &yes,
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
	}
}

// planLabel marks the pod enrolled. The pod has no such label, or Admit
// would have left it alone.
func (p *planner) planLabel(pod *corev1.Pod) {
	if pod.Labels == nil {
		p.ops = append(p.ops, Operation{Op: "add", Path: "/metadata/labels", Value: map[string]string{LabelCredentials: "true"}})
		return
	}
	p.ops = append(p.ops, Operation{Op: "add", Path: "/metadata/labels/" + escapePointer(LabelCredentials), Value: "true"})
}

func (p *planner) planAnnotations(pod *corev1.Pod) {
	if len(p.stripped) == 0 {
		return
	}
	b, err := json.Marshal(p.stripped)
	if err != nil {
		// Two strings per entry: this cannot fail, and a problem is the
		// honest answer if it somehow does.
		p.problems = append(p.problems, fmt.Sprintf("encoding the stripped-env annotation: %v", err))
		return
	}
	if pod.Annotations == nil {
		p.ops = append(p.ops, Operation{Op: "add", Path: "/metadata/annotations", Value: map[string]string{AnnotationStrippedEnv: string(b)}})
		return
	}
	p.ops = append(p.ops, Operation{Op: "add", Path: "/metadata/annotations/" + escapePointer(AnnotationStrippedEnv), Value: string(b)})
}

// escapePointer escapes one JSON Pointer reference token (RFC 6901).
func escapePointer(token string) string {
	return strings.NewReplacer("~", "~0", "/", "~1").Replace(token)
}
