# Worker-Image für studio (KI-Video-Pipeline): worker-comfyui + Zwischenbilder (RIFE) für die Nachbearbeitung.
# Modelle (Wan, Qwen-Image-Edit, Upscaler, ACE-Step) liegen am RunPod Network Volume, nicht im Image.
FROM runpod/worker-comfyui:5.10.0-base

# pkg_resources fehlt im Basis-Image (setuptools) – manche Node-Abhängigkeiten brauchen es beim Installieren
RUN pip install --no-cache-dir setuptools

# Custom Node: ComfyUI-Frame-Interpolation (RIFE VFI) aus der Comfy-Registry
RUN comfy-node-install comfyui-frame-interpolation

# RIFE-Gewichte vorab laden (über die Download-Funktion des Knotens, mit Fallback-Spiegeln);
# schlägt das fehl, lädt der Knoten beim ersten Lauf nach – der Build bricht deshalb nicht ab.
RUN cd /comfyui && python -c "import sys; sys.path.insert(0, '.'); sys.path.insert(0, 'custom_nodes/comfyui-frame-interpolation'); from vfi_utils import load_file_from_github_release as l; print(l('rife', 'rife47.pth'))" || echo "RIFE-Gewichte werden zur Laufzeit geladen"
RUN ls -la /comfyui/custom_nodes/comfyui-frame-interpolation/ckpts/rife 2>/dev/null || true

# studio-Knoten: Video von URL laden (große Eingaben jenseits der 10-MiB-Grenze von /run)
COPY studio_knoten /comfyui/custom_nodes/studio_knoten
