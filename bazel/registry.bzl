"""Where Crachá's images are published: ONE setting.

Every published coordinate is derived from the constants below: the
`image_push` of each `go_image` (//broker:image_push, //csi:image_push,
//webhook:image_push). Nothing else may spell the registry out.

The coordinates:

    <IMAGE_REGISTRY>/<IMAGE_NAMESPACE>/broker
    <IMAGE_REGISTRY>/<IMAGE_NAMESPACE>/csi
    <IMAGE_REGISTRY>/<IMAGE_NAMESPACE>/webhook

Repositories are not prefixed with the project name: the namespace already is
the project.

Keep each assignment below on ONE line, exactly `NAME = "value"`, so a script
can read it with a line-anchored grep.
"""

# Registry host.
IMAGE_REGISTRY = "quay.io"

# Organization under the host. Quay has NO nested repositories: everything is
# `<host>/<namespace>/<name>`, one path segment after the org.
IMAGE_NAMESPACE = "cracha"

def image_repository(component):
    """Repository path (no host) of a component's image.

    Args:
      component: "broker", "csi" or "webhook".

    Returns:
      e.g. "cracha/csi".
    """
    return "{}/{}".format(IMAGE_NAMESPACE, component)

def image_reference(component):
    """Host-qualified image repository of a component.

    Args:
      component: "broker", "csi" or "webhook".

    Returns:
      e.g. "quay.io/cracha/csi".
    """
    return "{}/{}".format(IMAGE_REGISTRY, image_repository(component))
