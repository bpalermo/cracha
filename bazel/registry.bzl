"""Where Crachá's images and chart are published: ONE setting.

Every published coordinate is derived from the constants below: the
`image_push` of each `go_image` (//broker:image_push, //agent:image_push,
//webhook:image_push, //third_party/spicedb:image_push), the chart push
(//charts/cracha:cracha.push_registry) and the chart's default image
repositories (charts/cracha/values.yaml, which takes each from its
image_push). Shell and the workflows read it through
bazel/registry.sh, and bazel/check-registry-config.sh fails CI on a registry
spelled out anywhere else. Nothing else may spell the registry out.

The coordinates:

    <IMAGE_REGISTRY>/<IMAGE_NAMESPACE>/broker
    <IMAGE_REGISTRY>/<IMAGE_NAMESPACE>/agent
    <IMAGE_REGISTRY>/<IMAGE_NAMESPACE>/webhook
    <IMAGE_REGISTRY>/<IMAGE_NAMESPACE>/spicedb       (SpiceDB: upstream plus a patch)
    oci://<IMAGE_REGISTRY>/<IMAGE_NAMESPACE>/cracha  (the chart)

Repositories are not prefixed with the project name: the namespace already is
the project. The chart is `cracha` because no image is.

Keep each assignment below on ONE line, exactly `NAME = "value"`, so a script
can read it with a line-anchored grep.
"""

# Registry host.
IMAGE_REGISTRY = "quay.io"

# Organization under the host. Quay has NO nested repositories: everything is
# `<host>/<namespace>/<name>`, one path segment after the org.
IMAGE_NAMESPACE = "cracha"

# Where cosign's keyless signature lands on IMAGE_REGISTRY, which the publish
# workflow ASSERTS for every digest it signs: "referrer" (an OCI 1.1 referrer
# and no tag -- a registry that serves the Referrers API, as quay.io does) or
# "tag" (cosign 3's `sha256-<hex>` fallback tag -- a registry without it).
SIGNATURE_LAYOUT = "referrer"

def image_repository(component):
    """Repository path (no host) of a component's image.

    Args:
      component: "broker", "agent", "webhook" or "spicedb".

    Returns:
      e.g. "cracha/agent".
    """
    return "{}/{}".format(IMAGE_NAMESPACE, component)

def image_reference(component):
    """Host-qualified image repository of a component.

    Args:
      component: "broker", "agent", "webhook" or "spicedb".

    Returns:
      e.g. "quay.io/cracha/agent".
    """
    return "{}/{}".format(IMAGE_REGISTRY, image_repository(component))

def chart_push_url():
    """The OCI base `helm push <chart>.tgz` is given (scheme, no chart name).

    `helm push` appends the packaged chart's Chart.yaml `name:` to this base and
    uses the chart version as the tag, so the repository a chart lands in is
    chart_registry_url(<name>).

    Returns:
      "oci://quay.io/cracha".
    """
    return "oci://{}/{}".format(IMAGE_REGISTRY, IMAGE_NAMESPACE)

def chart_registry_url(chart):
    """The host-qualified OCI repository a chart is pushed to (no scheme, no tag).

    Consumers pull it with `helm pull oci://<this> --version <X.Y.Z>`.

    Args:
      chart: the Chart.yaml name, "cracha".

    Returns:
      e.g. "quay.io/cracha/cracha".
    """
    return "{}/{}/{}".format(IMAGE_REGISTRY, IMAGE_NAMESPACE, chart)
