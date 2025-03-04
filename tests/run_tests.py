import os
import sys
import unittest
import coverage

# Set up coverage
cov = coverage.Coverage(
    branch=True,
    source=['src'],
    omit=[
        '*/tests/*',
        '*/venv/*',
        '*/__init__.py'
    ]
)
cov.start()

# Get the project root directory
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Add the project root to Python path
sys.path.insert(0, project_root)

# Discover and run tests
loader = unittest.TestLoader()
start_dir = os.path.join(project_root, 'tests')
suite = loader.discover(start_dir, pattern='test_*.py')

runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)

# Stop coverage and generate report
cov.stop()
cov.save()
cov.report()
cov.html_report(directory='coverage_html')

# Exit with appropriate status code
sys.exit(not result.wasSuccessful()) 