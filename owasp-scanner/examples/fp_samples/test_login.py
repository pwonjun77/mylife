from app import login

TEST_USER = "tester"
password = "not-a-real-password-123"


def test_login_success():
    assert login(TEST_USER, password)
