# Using 9Router with Clearwing

9Router is a local OpenAI-compatible AI gateway that provides access to multiple providers (Qwen, Claude, GPT, Gemini, etc.) through a single endpoint with automatic fallback and token optimization.

## Prerequisites

Ensure 9Router is installed and running:

```powershell
# Start 9Router (system tray mode recommended)
9router --tray

# Or with visible logs for debugging
9router --no-browser -l
```

The dashboard runs at: http://localhost:20128/dashboard

## Quick Setup

### Option 1: Use the Setup Wizard

```bash
clearwing setup
```

Select **"9Router (local AI gateway)"** from the menu. The wizard will:
- Set base URL to `http://127.0.0.1:20128/v1`
- Default model to `medium` (balanced combo)
### Option 1: Use the Setup Wizard (Recommended)

```bash
clearwing setup
```

Select **"9Router (local AI gateway)"** from the menu. You'll need:
- **Base URL**: `http://127.0.0.1:20128/v1` (pre-filled)
- **Model**: `medium` or `qwen3.7-plus` (your choice)
- **API Key**: Generate one from the 9Router dashboard (see below)

### Getting a 9Router API Key

1. Open the 9Router dashboard: http://localhost:20128/dashboard
2. Click **"API Keys"** in the sidebar
3. Click **"Generate New Key"**
4. Copy the key (starts with `sk-9r-...`)
5. Use it when configuring Clearwing

### Option 2: Environment Variables

```powershell
$env:CLEARWING_BASE_URL = "http://127.0.0.1:20128/v1"
$env:CLEARWING_MODEL = "medium"
$env:CLEARWING_API_KEY = "sk-9r-your-key-here"  # from dashboard
```

### Option 3: Direct Configuration

Edit `~/.clearwing/config.yaml`:

```yaml
provider:
  adapter: openai
  base_url: http://127.0.0.1:20128/v1
  api_key: sk-9r-your-key-here  # from dashboard → API Keys
  model: medium
```

Check live models via the dashboard or CLI:

```powershell
# View all available models and combos
curl http://127.0.0.1:20128/v1/models | ConvertFrom-Json | Select -ExpandProperty data | Select id, owned_by
```

Key models for testing:

| Model | Type | Description |
|-------|------|-------------|
| `medium` | Combo | Balanced daily driver with fallback chain |
| `qwen3.5plus` | Combo | Qwen 3.5 optimized |
| `qwen3.7-plus` | Combo | **Qwen 3.7+** (latest, recommended for testing) |
| `cx/gpt-5.5` | Routed | GPT-5.5 via Codex backend |
| `ag/claude-sonnet-4-6` | Routed | Claude Sonnet 4.6 via Anthropic gateway |
| `Nvidia_Super` | Combo | Nvidia Nemotron Ultra + others |

## Testing with Qwen 3.7+

For source-hunting and vulnerability analysis with Qwen 3.7+:

```bash
# Set environment
$env:CLEARWING_BASE_URL = "http://127.0.0.1:20128/v1"
$env:CLEARWING_MODEL = "qwen3.7-plus"

# Run a test scan
clearwing scan 192.168.1.10 -p 22,80,443 --detect-services

# Or source-hunt a repo
clearwing sourcehunt https://github.com/example/project --depth minimal
```

## Managing Combos

To customize which models are in a combo (like `medium` or `qwen3.7-plus`):

1. Open dashboard: http://localhost:20128/dashboard/combos
2. Edit the combo
3. Drag to reorder the fallback chain
4. Restart 9Router if needed

## Troubleshooting

### Connection Refused
```
Error: Connection refused to http://127.0.0.1:20128/v1
```
→ Start 9Router first: `9router --tray`

### Invalid API Key / Missing API Key
```
Error: {"error":{"message":"Invalid API key",...}}
```
→ Generate an API key from the 9Router dashboard (http://localhost:20128/dashboard → API Keys) and set it in your config or `CLEARWING_API_KEY` env var.

### Empty Content but Reasoning Present
Some reasoning models return answers in `reasoning_content` instead of `content`. Clearwing's LLM client handles this automatically via the `_normalize_response` path.

### Token Bloat
9Router enables RTK (Response Token Kompression) by default, reducing tool output tokens by 20-40%. Verify it's enabled in the dashboard settings.

## Performance Tips

- Use `qwen3.7-plus` for code analysis and vulnerability hunting (optimized for technical tasks)
- Use `medium` for general ReAct agent loops (balanced cost/performance)
- Use specific routed models like `cx/gpt-5.5` when you need guaranteed provider behavior
- Monitor token usage in the 9Router dashboard to optimize combo chains

## References

- 9Router docs: See `skill://9router` for full details
- Clearwing providers: [`docs/providers.md`](providers.md)
- 9Router dashboard: http://localhost:20128/dashboard
