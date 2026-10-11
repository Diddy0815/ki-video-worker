# Worker-Image für studio (KI-Video-Pipeline): worker-comfyui + Zwischenbilder (RIFE) für die Nachbearbeitung.
# Modelle (Wan, Qwen-Image-Edit, Upscaler, ACE-Step) liegen am RunPod Network Volume, nicht im Image.
FROM runpod/worker-comfyui:5.10.0-base

# Custom Node: ComfyUI-Frame-Interpolation (RIFE VFI) aus der Comfy-Registry
RUN comfy-node-install comfyui-frame-interpolation

# RIFE-Gewichte vorab laden, damit der Worker beim Kaltstart nichts nachladen muss
RUN mkdir -p /comfyui/custom_nodes/comfyui-frame-interpolation/ckpts/rife \
    && cd /comfyui/custom_nodes/comfyui-frame-interpolation/ckpts/rife \
    && (wget -q -O rife47.pth https://github.com/styler00dollar/VSGAN-tensorrt-docker/releases/download/models/rife47.pth \
        || wget -q -O rife47.pth https://huggingface.co/Fannovel16/ComfyUI-Frame-Interpolation/resolve/main/rife47.pth) \
    && ls -la
