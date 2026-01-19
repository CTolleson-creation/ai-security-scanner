# Architecture Documentation

## System Overview

The AI Security Scanner is built as a modular Python application with three main layers:

### Layer 1: Detection Engine
- **Purpose**: Core vulnerability detection logic
- **Components**: Individual detector modules for each OWASP category
- **Input**: Test payloads and LLM responses
- **Output**: Structured vulnerability reports

### Layer 2: Interface Layer
- **Web UI**: Streamlit-based interactive interface
- **CLI**: Command-line demo and batch processing
- **API**: (Future) RESTful API for integrations

### Layer 3: Data Layer
- **Test Cases**: JSON-formatted attack payloads
- **Configuration**: Environment-based settings
- **Results**: (Future) Database storage for historical scans

## Component Details

### PromptInjectionDetector

**File**: `src/detectors/prompt_injection.py`

**Responsibilities**:
1. Load test cases from JSON
2. Analyze LLM responses for vulnerability indicators
3. Calculate confidence scores
4. Generate remediation recommendations

**Key Methods**:
```python
class PromptInjectionDetector:
    def _load_test_cases() -> List[Dict]
    def get_test_payloads() -> List[Dict]
    def analyze_response(payload, response) -> Dict
    def generate_report_summary(results) -> Dict
```

**Detection Algorithm**:
1. Pattern matching against known exploit indicators
2. Behavioral analysis (unexpected compliance)
3. Confidence scoring based on response characteristics

### MockLLM

**File**: `src/mock_llm.py`

**Purpose**: Simulate LLM behavior for cost-free testing

**Modes**:
- `vulnerable`: Responds insecurely to demonstrate vulnerabilities
- `secure`: Responds with proper safeguards

**Use Cases**:
- Development without API costs
- Demos without external dependencies
- Baseline testing for detector accuracy

## Data Flow Diagram
```
┌─────────────┐
│   User      │
└──────┬──────┘
       │
       ▼
┌─────────────────────┐
│  Streamlit UI       │
│  (app.py)           │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│  Scanner Core       │
│  (detector modules) │
└──────┬──────────────┘
       │
       ├──────────────────┐
       ▼                  ▼
┌──────────────┐   ┌──────────────┐
│  Test Cases  │   │  Target LLM  │
│  (JSON)      │   │  (Mock/API)  │
└──────────────┘   └──────┬───────┘
                          │
                          ▼
                   ┌──────────────┐
                   │   Analysis   │
                   │   Engine     │
                   └──────┬───────┘
                          │
                          ▼
                   ┌──────────────┐
                   │   Report     │
                   │   Generator  │
                   └──────────────┘
```

## Security Considerations

### Input Validation
- All user inputs sanitized before processing
- JSON schemas validated before parsing
- Path traversal prevention in file operations

### API Key Management
- Keys stored in environment variables only
- `.env` file excluded from version control
- No hardcoded credentials in source

### Output Sanitization
- Responses truncated to prevent log injection
- Special characters escaped in reports
- XSS prevention in web interface

## Performance Optimization

### Current Performance
- **Scan Time**: <5 seconds for 8 tests (mock LLM)
- **Memory Usage**: ~50MB baseline
- **API Calls**: 1 per test case

### Optimization Strategies
- Concurrent test execution (future)
- Response caching for repeated scans
- Batch API requests where supported
- Progressive UI updates during scans

## Extension Points

### Adding New Vulnerability Detectors

1. Create new detector module in `src/detectors/`
2. Implement standard interface:
```python
   class NewDetector:
       def load_test_cases()
       def analyze_response()
       def generate_report_summary()
```
3. Register in scanner core
4. Add UI tab in Streamlit app

### Adding New Test Cases

1. Add to appropriate JSON file in `src/test_cases/`
2. Follow schema:
```json
   {
     "id": "XX-###",
     "category": "Category Name",
     "severity": "CRITICAL|HIGH|MEDIUM|LOW",
     "payload": "Attack string",
     "expected_behavior": "What should happen",
     "description": "Why this matters"
   }
```

## Testing Strategy

### Unit Tests (Coming Soon)
- Test each detector independently
- Mock LLM responses
- Validate scoring algorithms

### Integration Tests
- End-to-end scan workflows
- UI interaction testing
- API integration testing

### Performance Tests
- Scan time benchmarks
- Memory usage profiling
- API rate limit handling

## Deployment Options

### Local Development
```bash
streamlit run app.py
```

### Docker (Future)
```dockerfile
FROM python:3.11-slim
COPY . /app
RUN pip install -r requirements.txt
CMD ["streamlit", "run", "app.py"]
```

### Cloud Deployment (Future)
- AWS Lambda + API Gateway
- Google Cloud Run
- Heroku