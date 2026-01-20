# Changelog

All notable changes to the AI Security Scanner project will be documented in this file.

## [Week 2] - 2026-01-20

### Added
- **API Key Security Scanner** (`src/detectors/api_security.py`)
  - Detects 7+ types of exposed credentials
  - Supports text, file, and directory scanning
  - Safely masks credentials in output
  - Provides specific remediation guidance for each credential type
  
- **Security Scoring System** (`src/scoring.py`)
  - Calculates 0-100 security scores
  - Assigns letter grades (A+ through F)
  - Determines risk levels (Secure, Low, Medium, High, Critical)
  - Provides severity-based point deduction breakdown
  - Generates professional recommendations

- **Enhanced Streamlit Interface** (`app.py`)
  - Security score dashboard with metrics
  - Three scan types: Prompt Injection, API Security, Comprehensive
  - Real-time visual results
  - Tabbed interface for different scanning methods
  - Example test cases for demonstrations

- **Test Scripts**
  - `test_api_scanner.py` for credential detection testing

### Changed
- Updated `src/scanner.py` to integrate scoring system
- Enhanced result display functions with security scores
- Improved UI/UX with professional metrics and visualizations

### Technical Details
- Total lines of code: ~1,200+
- Detection patterns: 20+ prompt injection, 7+ credential types
- Test cases: 20+ examples

## [Week 1] - 2026-01-13

### Added
- **Project Structure**
  - Initial directory layout
  - Virtual environment setup
  - Git repository initialization
  - Dependencies installation

- **Prompt Injection Detector** (`src/detectors/prompt_injection.py`)
  - Pattern-based detection for common injection attacks
  - Risk scoring algorithm
  - Mock LLM for cost-free testing
  - JSON test case database

- **Core Scanner** (`src/scanner.py`)
  - Main orchestration logic
  - Multi-detector support architecture
  - Result aggregation

- **Basic Streamlit Interface**
  - Single-page web application
  - Prompt testing interface
  - Result visualization

- **Documentation**
  - README.md with project overview
  - ARCHITECTURE.md with technical details
  - USAGE_GUIDE.md with examples
  - MIT License

### Research Completed
- Deep dive into OWASP LLM Top 10 framework
- Mapped traditional security concepts to AI vulnerabilities
- Identified priority vulnerabilities for implementation

## [Week 0] - 2026-01-06

### Planning
- Defined project scope and goals
- Created 8-week development timeline
- Established success metrics
- Designed initial architecture

---

## Upcoming

### Week 3 (Planned)
- [ ] PDF/HTML report generation
- [ ] Insecure output handling detection
- [ ] Real LLM API integration (OpenAI/Anthropic)
- [ ] Executive summary dashboard

### Week 4 (Planned)
- [ ] Comprehensive testing and bug fixes
- [ ] Final documentation
- [ ] Demo video creation
- [ ] Portfolio presentation materials

---

## Version History

- **v0.2.0** (Week 2) - API Security Scanner + Scoring System
- **v0.1.0** (Week 1) - Initial Prompt Injection Detector
- **v0.0.1** (Week 0) - Project Planning