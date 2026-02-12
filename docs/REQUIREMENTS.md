# PenPard System Requirements

## Minimum Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 4 cores | 8+ cores |
| **RAM** | 8 GB | 16 GB |
| **Disk** | 20 GB free | 50 GB SSD |
| **Network** | 100 Mbps | 1 Gbps |

## GPU Requirements (for Local LLM)

If running local AI models (e.g. via Ollama):

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **GPU** | NVIDIA GTX 1660 | NVIDIA RTX 3080+ |
| **VRAM** | 6 GB | 12+ GB |
| **CUDA** | 11.0+ | 12.0+ |

> Note: GPU is optional if using cloud-based LLM providers (OpenAI, Anthropic, Google, etc.).

## Software Requirements

### Required

- **Operating System**: Windows 10/11 (64-bit)
- **Docker Desktop**: v4.0+ with WSL2 backend
- **Node.js**: v18+ (included in Docker)
- **Python**: v3.9+ (included in Docker)

### Optional (for full functionality)

- **Burp Suite Professional**: v2023.0+ with REST API enabled
- **MobSF**: v3.7+

## Network Requirements

| Port | Service | Description |
|------|---------|-------------|
| 3000 | Frontend | Next.js web interface |
| 4000 | Backend | Express API server |
| 5000 | VulnApp | Test vulnerable application |
| 1337 | Burp API | Burp Suite REST API |
| 8000 | MobSF | MobSF REST API |

## Docker Resource Allocation

```yaml
# Recommended docker-compose resource limits
services:
  backend:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
  frontend:
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 1G
```

## Browser Compatibility

| Browser | Minimum Version |
|---------|----------------|
| Chrome | 90+ |
| Firefox | 88+ |
| Edge | 90+ |
| Safari | 14+ |

## Performance Considerations

### Web Scanning
- Average scan time: 5-15 minutes per domain
- Memory usage: ~500MB per active scan
- Concurrent scans: Max 3 recommended

### Mobile Analysis
- APK upload limit: 100MB
- Analysis time: 2-5 minutes per APK
- Storage: ~200MB per analysis

## Scaling Recommendations

For enterprise deployment:

| Users | CPU | RAM | Storage |
|-------|-----|-----|---------|
| 1-5 | 4 cores | 8 GB | 50 GB |
| 5-20 | 8 cores | 16 GB | 100 GB |
| 20+ | 16+ cores | 32 GB | 500 GB |
