package mutate

import (
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// planner walks one pod and collects the patch operations it needs, the
// problems that make it unacceptable, and the warnings worth returning. It
// only reads the pod; the patch is built from paths and fresh values, never
// from a mutated copy, so the operations are easy to inspect in a test.
type planner struct {
	cfg    Config
	region string

	ops      []Operation
	problems []string
	warnings []string
	stripped []StrippedEnv
}

func (p *planner) plan(pod *corev1.Pod) {
	p.planVolume(pod)
	for i := range pod.Spec.InitContainers {
		p.planContainer(&pod.Spec.InitContainers[i], "/spec/initContainers/"+strconv.Itoa(i))
	}
	for i := range pod.Spec.Containers {
		p.planContainer(&pod.Spec.Containers[i], "/spec/containers/"+strconv.Itoa(i))
	}
	if len(p.problems) > 0 {
		return
	}
	p.planAnnotations(pod)
}

// volume is the CSI ephemeral inline volume (design 7.1).
func volume() corev1.Volume {
	readOnly := true
	return corev1.Volume{
		Name: VolumeName,
		VolumeSource: corev1.VolumeSource{
			CSI: &corev1.CSIVolumeSource{
				Driver:   Driver,
				ReadOnly: &readOnly,
			},
		},
	}
}

func mount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      VolumeName,
		MountPath: MountPath,
		ReadOnly:  true,
	}
}

func (p *planner) planVolume(pod *corev1.Pod) {
	for _, v := range pod.Spec.Volumes {
		if v.Name != VolumeName {
			continue
		}
		if v.CSI == nil || v.CSI.Driver != Driver {
			p.problems = append(p.problems,
				fmt.Sprintf("volume %q is not the %s CSI volume", VolumeName, Driver))
		}
		return
	}
	if pod.Spec.Volumes == nil {
		p.ops = append(p.ops, Operation{Op: "add", Path: "/spec/volumes", Value: []corev1.Volume{volume()}})
	} else {
		p.ops = append(p.ops, Operation{Op: "add", Path: "/spec/volumes/-", Value: volume()})
	}
}

// managedEnv is what every container ends up with.
func (p *planner) managedEnv() []corev1.EnvVar {
	return []corev1.EnvVar{
		{Name: EnvCredentialsURI, Value: p.cfg.BrokerURL},
		{Name: EnvTokenFile, Value: TokenPath},
		{Name: EnvRegion, Value: p.region},
	}
}

func (p *planner) planContainer(c *corev1.Container, base string) {
	p.planMounts(c, base)
	p.planEnv(c, base)
}

func (p *planner) planMounts(c *corev1.Container, base string) {
	mounted := false
	for _, vm := range c.VolumeMounts {
		mp := path.Clean(vm.MountPath)
		switch {
		case mp == MountPath && vm.Name == VolumeName:
			mounted = true
		case mp == MountPath:
			p.problems = append(p.problems,
				fmt.Sprintf("container %q mounts volume %q at %s, which is reserved for the %s volume",
					c.Name, vm.Name, MountPath, VolumeName))
		case strings.HasPrefix(mp, MountPath+"/"):
			p.problems = append(p.problems,
				fmt.Sprintf("container %q mounts volume %q at %s, inside the %s volume's %s",
					c.Name, vm.Name, vm.MountPath, VolumeName, MountPath))
		}
	}
	if mounted {
		return
	}
	if c.VolumeMounts == nil {
		p.ops = append(p.ops, Operation{Op: "add", Path: base + "/volumeMounts", Value: []corev1.VolumeMount{mount()}})
	} else {
		p.ops = append(p.ops, Operation{Op: "add", Path: base + "/volumeMounts/-", Value: mount()})
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

func (p *planner) planAnnotations(pod *corev1.Pod) {
	set := map[string]string{}
	if pod.Annotations[AnnotationInjected] != "true" {
		set[AnnotationInjected] = "true"
	}
	if len(p.stripped) > 0 {
		b, err := json.Marshal(p.stripped)
		if err != nil {
			// Two strings per entry: this cannot fail, and a problem is the
			// honest answer if it somehow does.
			p.problems = append(p.problems, fmt.Sprintf("encoding the stripped-env annotation: %v", err))
			return
		}
		set[AnnotationStrippedEnv] = string(b)
	}
	if len(set) == 0 {
		return
	}
	if pod.Annotations == nil {
		p.ops = append(p.ops, Operation{Op: "add", Path: "/metadata/annotations", Value: set})
		return
	}
	// In order, so the patch is stable.
	for _, key := range []string{AnnotationInjected, AnnotationStrippedEnv} {
		if value, ok := set[key]; ok {
			p.ops = append(p.ops, Operation{Op: "add", Path: "/metadata/annotations/" + escapePointer(key), Value: value})
		}
	}
}

// escapePointer escapes one JSON Pointer reference token (RFC 6901).
func escapePointer(token string) string {
	return strings.NewReplacer("~", "~0", "/", "~1").Replace(token)
}
