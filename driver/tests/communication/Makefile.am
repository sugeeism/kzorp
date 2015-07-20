check_SCRIPTS = KZorpTestCaseDispatchers.py KZorpTestCaseServices.py KZorpTestCaseTransaction.py KZorpTestCaseVersion.py KZorpTestCaseZones.py
AM_TESTS_ENVIRONMENT = export PYTHONPATH=$(top_srcdir)/driver/tests/base:$(top_srcdir)/pylib;

TEST_EXTENSIONS = .py
PY_LOG_COMPILER = $(PYTHON)
AM_PY_LOG_FLAGS = -B

TESTS = $(check_SCRIPTS)
EXTRA_DIST = $(check_SCRIPTS) KZorpBaseTestCaseBind.py KZorpBaseTestCaseDispatchers.py KZorpBaseTestCaseZones.py
