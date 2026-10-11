# ki-video-worker

Docker-Image für den RunPod-Serverless-Endpoint von **studio** (KI-Video-Pipeline):
`runpod/worker-comfyui:5.10.0-base` plus ComfyUI-Frame-Interpolation (RIFE) für Zwischenbilder.
Wird von der GitHub-Action nach `ghcr.io/diddy0815/ki-video-worker:latest` gebaut (öffentlich, enthält keine Geheimnisse).
Modelle liegen am Network Volume. Hauptprojekt: Diddy0815/ki-video-pipeline (privat).
