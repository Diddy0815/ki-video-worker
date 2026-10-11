"""studio-Knoten für den Worker: Video von einer URL laden (umgeht die 10-MiB-Grenze von RunPod /run)."""
import os
import urllib.request

import folder_paths
from comfy_api.input_impl import VideoFromFile


class VideoAusURL:
    @classmethod
    def INPUT_TYPES(cls):
        return {"required": {"url": ("STRING", {"default": ""}), "name": ("STRING", {"default": "eingang.mp4"})}}

    RETURN_TYPES = ("VIDEO",)
    RETURN_NAMES = ("video",)
    FUNCTION = "laden"
    CATEGORY = "studio"

    def laden(self, url, name):
        pfad = os.path.join(folder_paths.get_input_directory(), os.path.basename(name))
        anfrage = urllib.request.Request(url, headers={"User-Agent": "studio-worker/1.0"})
        with urllib.request.urlopen(anfrage, timeout=120) as antwort, open(pfad, "wb") as ziel:
            while True:
                stueck = antwort.read(1 << 20)
                if not stueck:
                    break
                ziel.write(stueck)
        return (VideoFromFile(pfad),)

    @classmethod
    def IS_CHANGED(cls, url, name):
        return url


NODE_CLASS_MAPPINGS = {"VideoAusURL": VideoAusURL}
NODE_DISPLAY_NAME_MAPPINGS = {"VideoAusURL": "Video aus URL (studio)"}
