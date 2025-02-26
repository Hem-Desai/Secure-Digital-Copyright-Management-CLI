import unittest
import coverage
import sys
import os

def run_tests_with_coverage():
    """Run all tests with coverage reporting"""
    # Start coverage measurement
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
    
    # Discover and run tests
    loader = unittest.TestLoader()
    start_dir = os.path.dirname(os.path.abspath(__file__))
    suite = loader.discover(start_dir, pattern='test_*.py')
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Stop coverage measurement
    cov.stop()
    cov.save()
    
    # Generate reports
    print('\nCoverage Summary:')
    cov.report()
    
    # Generate HTML report
    cov.html_report(directory='coverage_html')
    print('\nDetailed coverage report generated in coverage_html/index.html')
    
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_tests_with_coverage()
    sys.exit(0 if success else 1) 