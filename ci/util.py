import json
import urllib.request
import urllib.parse

from typing import Dict, List


def get_registry_uri(namespace: str,
                     gitlab_uri: str = "https://gitlab.com") -> str:
    """
    Construct a v4 API URI pointing the namespaced project's image registry.

    :param namespace: GitLab project namespace, e.g. "libvirt/libvirt"
    :param gitlab_uri: GitLab base URI, can be a private deployment
    :param api_version: GitLab REST API version number
    :return: URI pointing to a namespaced project's image registry
    """

    # this converts something like "libvirt/libvirt" to "libvirt%2Flibvirt"
    namespace_urlenc = urllib.parse.quote_plus(namespace)

    project_uri = f"{gitlab_uri}/api/v4/projects/{namespace_urlenc}"

    uri = project_uri + "/registry/repositories"
    return uri


def get_registry_images(uri: str) -> List[Dict]:
    """
    List all container images that are currently available in the given GitLab
    project.

    :param uri: URI pointing to a GitLab instance's image registry
    :return: list of container image names
    """

    r = urllib.request.urlopen(uri + "?per_page=100")

    # read the HTTP response and load the JSON part of it
    return json.loads(r.read().decode())


def get_image_distro(image_name: str) -> str:
    """
    Extract the name of the distro in the GitLab image registry name, e.g.
        ci-debian-9-cross-mipsel --> debian-9

    :param image_name: name of the GitLab registry image
    :return: distro name as a string
    """
    name_prefix = "ci-"
    name_suffix = "-cross-"

    distro = image_name[len(name_prefix):]

    index = distro.find(name_suffix)
    if index > 0:
        distro = distro[:index]

    return distro


def get_registry_stale_images(registry_uri: str,
                              supported_distros: List[str]) -> Dict[str, int]:
    """
    Check the GitLab image registry for images that we no longer support and
    which should be deleted.

    :param uri: URI pointing to a GitLab instance's image registry
    :param supported_distros: list of hosts supported by lcitool
    :return: dictionary formatted as: {<gitlab_image_name>: <gitlab_image_id>}
    """

    images = get_registry_images(registry_uri)

    stale_images = {}
    for img in images:
        if get_image_distro(img["name"]) not in supported_distros:
            stale_images[img["name"]] = img["id"]

    return stale_images
