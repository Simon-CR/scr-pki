# Contributing to HomeLab PKI Platform

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inspiring community for all. Please be respectful and constructive in all interactions.

### Expected Behavior

- Use welcoming and inclusive language
- Be respectful of differing viewpoints
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

### Unacceptable Behavior

- Harassment, trolling, or discriminatory comments
- Personal or political attacks
- Public or private harassment
- Publishing others' private information
- Other conduct inappropriate in a professional setting

## How to Contribute

### Reporting Bugs

Before creating a bug report, please check existing issues to avoid duplicates.

**Good bug reports include:**

- Clear, descriptive title
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Environment details (OS, Docker version, etc.)
- Screenshots or logs (if applicable)
- Possible fix (if you have ideas)

**Bug Report Template:**

```markdown
**Description**
Clear description of the bug.

**To Reproduce**
1. Go to '...'
2. Click on '...'
3. See error

**Expected Behavior**
What you expected to happen.

**Actual Behavior**
What actually happened.

**Environment**
- OS: Ubuntu 22.04
- Docker: 24.0.5
- Docker Compose: 2.20.0
- Browser: Firefox 118

**Screenshots/Logs**
Add screenshots or logs here.

**Additional Context**
Any other relevant information.
```

### Suggesting Features

Feature suggestions are welcome! Please provide:

- Clear description of the feature
- Use case / problem it solves
- Proposed implementation (if you have ideas)
- Alternative solutions considered
- Impact on existing functionality

**Feature Request Template:**

```markdown
**Is your feature request related to a problem?**
A clear description of the problem.

**Describe the solution you'd like**
A clear description of what you want to happen.

**Describe alternatives you've considered**
Alternative solutions or features you've considered.

**Additional context**
Any other context, screenshots, or examples.

**Would you be willing to implement this?**
Yes/No/Maybe with guidance
```

### Pull Requests

#### Before You Start

1. Check existing issues and PRs
2. For major changes, open an issue first to discuss
3. Fork the repository
4. Create a feature branch from `develop`

#### Development Process

1. **Clone your fork:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/pki.git
   cd pki
   git remote add upstream https://github.com/ORIGINAL_OWNER/pki.git
   ```

2. **Create a branch:**
   ```bash
   git checkout -b feature/your-feature-name develop
   ```

   Branch naming:
   - `feature/` - New features
   - `bugfix/` - Bug fixes
   - `hotfix/` - Urgent fixes
   - `docs/` - Documentation changes
   - `refactor/` - Code refactoring
   - `test/` - Test additions/changes

3. **Make your changes:**
   - Follow code style guidelines
   - Add tests for new features
   - Update documentation
   - Keep commits atomic and well-described

4. **Test your changes:**
   ```bash
   # Backend tests
   cd backend
   pytest
   
   # Frontend tests
   cd frontend
   npm test
   
   # Integration tests
   docker compose -f docker-compose.test.yml up --abort-on-container-exit
   ```

5. **Commit your changes:**
   ```bash
   git add .
   git commit -m "feat(certificates): add certificate templates"
   ```

   Follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat`: New feature
   - `fix`: Bug fix
   - `docs`: Documentation only
   - `style`: Code style changes (formatting)
   - `refactor`: Code refactoring
   - `test`: Adding or updating tests
   - `chore`: Maintenance tasks

6. **Push to your fork:**
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create Pull Request:**
   - Go to GitHub and create PR from your branch to `develop`
   - Fill out the PR template
   - Link related issues
   - Request review

#### Pull Request Template

```markdown
**Description**
Brief description of changes.

**Type of Change**
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature causing existing functionality to break)
- [ ] Documentation update

**Related Issues**
Fixes #123, relates to #456

**How Has This Been Tested?**
- [ ] Unit tests
- [ ] Integration tests
- [ ] Manual testing

**Checklist**
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests added/updated
- [ ] All tests passing
- [ ] Dependent changes merged

**Screenshots** (if applicable)
Add screenshots here.

**Additional Notes**
Any additional information.
```

#### Code Review Process

1. Maintainer reviews PR
2. Automated checks run (tests, linting)
3. Reviewer provides feedback
4. You address feedback
5. Reviewer approves
6. Maintainer merges

**What reviewers look for:**
- Correctness
- Test coverage
- Code quality
- Documentation
- Performance
- Security
- Breaking changes

## Development Guidelines

### Code Style

#### Python (Backend)

Follow [PEP 8](https://pep8.org/) style guide.

```python
# Good
def issue_certificate(
    common_name: str,
    validity_days: int = 3650,
    key_size: int = 4096
) -> Certificate:
    """
    Issue a new certificate.
    
    Args:
        common_name: Primary hostname
        validity_days: Validity period in days
        key_size: RSA key size in bits
        
    Returns:
        Issued certificate
    """
    pass

# Bad
def IssueCert(cn,days=3650,ks=4096):
    pass
```

**Tools:**
```bash
# Format
black backend/

# Sort imports
isort backend/

# Lint
flake8 backend/
pylint backend/

# Type check
mypy backend/
```

#### TypeScript (Frontend)

Follow [Airbnb JavaScript Style Guide](https://github.com/airbnb/javascript).

```typescript
// Good
interface CertificateProps {
  certificate: Certificate;
  onSelect: (id: string) => void;
}

export const CertificateCard: React.FC<CertificateProps> = ({
  certificate,
  onSelect
}) => {
  return (
    <div onClick={() => onSelect(certificate.id)}>
      <h3>{certificate.commonName}</h3>
    </div>
  );
};

// Bad
export function CertCard(props:any){
  return <div onClick={()=>{props.onSelect(props.cert.id)}}>
    <h3>{props.cert.commonName}</h3></div>
}
```

**Tools:**
```bash
# Format
npm run format

# Lint
npm run lint

# Type check
npm run type-check
```

### Testing Guidelines

#### Unit Tests

Test individual functions/components in isolation.

```python
# backend/tests/test_certificate_service.py
def test_issue_certificate():
    """Test certificate issuance"""
    cert = issue_certificate(
        common_name="test.local",
        validity_days=365
    )
    assert cert.common_name == "test.local"
    assert cert.status == "active"
```

```typescript
// frontend/src/components/__tests__/CertificateCard.test.tsx
describe('CertificateCard', () => {
  it('renders certificate name', () => {
    const cert = { id: '1', commonName: 'test.local' };
    render(<CertificateCard certificate={cert} onSelect={jest.fn()} />);
    expect(screen.getByText('test.local')).toBeInTheDocument();
  });
});
```

#### Integration Tests

Test interaction between components.

```python
def test_certificate_issuance_flow(client, admin_token):
    """Test complete certificate issuance flow"""
    response = client.post(
        "/api/v1/certificates/issue",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"common_name": "test.local"}
    )
    assert response.status_code == 200
    cert_id = response.json()["id"]
    
    # Verify certificate exists
    response = client.get(
        f"/api/v1/certificates/{cert_id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
```

#### Test Coverage

Aim for:
- Unit test coverage: 80%+
- Integration test coverage: 60%+
- Critical paths: 100%

```bash
# Check coverage
pytest --cov=app --cov-report=html
npm test -- --coverage
```

### Documentation

#### Code Documentation

All public functions/classes should have docstrings.

```python
def issue_certificate(
    db: Session,
    common_name: str,
    validity_days: int = 3650
) -> Certificate:
    """
    Issue a new SSL/TLS certificate.
    
    This function generates a new certificate signed by the CA,
    stores the private key in Vault, and saves metadata in the database.
    
    Args:
        db: Database session for storing certificate metadata
        common_name: Primary hostname for the certificate (FQDN or IP)
        validity_days: Certificate validity period in days (1-7300)
        
    Returns:
        Certificate: The issued certificate object with metadata
        
    Raises:
        ValueError: If common_name is invalid or validity_days out of range
        VaultError: If key storage in Vault fails
        DatabaseError: If database operation fails
        
    Example:
        >>> cert = issue_certificate(db, "homeassistant.local", 3650)
        >>> print(f"Serial: {cert.serial_number}")
        Serial: 1A:2B:3C:4D:5E:6F
        
    Note:
        The private key is stored securely in Vault and never exposed
        through the API after initial issuance.
    """
```

#### User Documentation

Update docs when:
- Adding new features
- Changing APIs
- Modifying configuration
- Changing deployment process

### Security Guidelines

#### Security Checklist

- [ ] Input validation on all user inputs
- [ ] No secrets in code or logs
- [ ] SQL injection prevention (use ORMs)
- [ ] XSS prevention (escape output)
- [ ] CSRF protection on state-changing operations
- [ ] Authentication required for sensitive operations
- [ ] Authorization checks (user can access resource)
- [ ] Secure password hashing (bcrypt)
- [ ] Rate limiting on API endpoints
- [ ] Audit logging for security events

#### Reporting Security Vulnerabilities

**Do NOT create public issues for security vulnerabilities.**

Instead:
1. Email: security@example.com (replace with actual email)
2. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
3. Wait for acknowledgment (within 48 hours)
4. Coordinate disclosure timeline

## Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions, ideas, and general discussion
- **Discord** (if available): Real-time chat
- **Email**: For private matters

### Getting Help

- Check [documentation](docs/)
- Search [existing issues](https://github.com/OWNER/pki/issues)
- Ask in [GitHub Discussions](https://github.com/OWNER/pki/discussions)
- Read [FAQ](docs/FAQ.md)

### Recognition

Contributors are recognized in:
- README.md contributors section
- Release notes
- Project documentation

## Development Resources

### Useful Links

- [Project Documentation](docs/)
- [API Documentation](docs/API.md)
- [Development Guide](docs/DEVELOPMENT.md)
- [Architecture Overview](docs/ARCHITECTURE.md)

### Learning Resources

**PKI/Cryptography:**
- [PKI Basics](https://en.wikipedia.org/wiki/Public_key_infrastructure)
- [X.509 Certificates](https://en.wikipedia.org/wiki/X.509)
- [OpenSSL Documentation](https://www.openssl.org/docs/)

**FastAPI:**
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [FastAPI Tutorial](https://fastapi.tiangolo.com/tutorial/)

**React:**
- [React Documentation](https://react.dev/)
- [TypeScript Handbook](https://www.typescriptlang.org/docs/)

**Docker:**
- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)

**HashiCorp Vault:**
- [Vault Documentation](https://www.vaultproject.io/docs)
- [Vault Tutorial](https://learn.hashicorp.com/vault)

## Release Process

### Versioning

We use [Semantic Versioning](https://semver.org/):

- MAJOR: Breaking changes
- MINOR: New features (backwards compatible)
- PATCH: Bug fixes (backwards compatible)

### Release Checklist

- [ ] All tests passing
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped
- [ ] Release notes prepared
- [ ] Tagged in git
- [ ] Docker images built and pushed
- [ ] GitHub release created

### Changelog Format

```markdown
## [1.2.0] - 2025-11-13

### Added
- Certificate templates for quick issuance (#123)
- Support for ECDSA keys (#145)

### Changed
- Improved monitoring dashboard UI (#134)
- Updated dependencies

### Fixed
- Certificate expiration calculation bug (#156)
- Vault connection retry logic (#167)

### Security
- Fixed XSS vulnerability in certificate name display (#178)
```

## Project Governance

### Maintainers

Current maintainers:
- @maintainer1 (Lead maintainer)
- @maintainer2 (Backend)
- @maintainer3 (Frontend)

### Decision Making

- Minor changes: Any maintainer can approve
- Major changes: Consensus of maintainers
- Breaking changes: Discussed in issue first

### Becoming a Maintainer

Contributors with significant, sustained contributions may be invited to become maintainers.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

If you have questions about contributing:
- Open a [GitHub Discussion](https://github.com/OWNER/pki/discussions)
- Check the [FAQ](docs/FAQ.md)
- Contact maintainers

Thank you for contributing! 🎉
