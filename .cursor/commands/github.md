# GitHub Quick Access

Simple command for quick GitHub repository navigation and branch information.

## Usage:

Type `/github` to get repository links and current branch status.

## Repository Links:
- **Home**: https://github.com/elastiflow/mermin
- **Issues**: https://github.com/elastiflow/mermin/issues
- **Pull Requests**: https://github.com/elastiflow/mermin/pulls  
- **Actions**: https://github.com/elastiflow/mermin/actions
- **New Issue**: https://github.com/elastiflow/mermin/issues/new

## Branch Information:
```bash
# Current branch and status
git branch --show-current
git status --short

# Recent commits  
git log --oneline -5
```

## Quick Compare:
- **Compare to main**: https://github.com/elastiflow/mermin/compare/main...$(git branch --show-current)

**Note**: This command provides fast GitHub access without leaving your development environment.