from datetime import datetime, timedelta, timezone

import jwt

from security.auth import (
    create_access_token,
    create_refresh_token,
    verify_token,
    decode_token_payload,
    SECRET_KEY,
    ALGORITHM,
)



# ==========================================================
# JWT VALIDATION TESTS
# ==========================================================


def test_valid_access_token():

    """
    Verify that a valid access token is accepted.
    """

    token = create_access_token(
        {
            "sub": "testuser"
        }
    )


    assert verify_token(
        token,
        expected_type="access"
    ) == "testuser"


    print(
        "   ✅ Access token accepted"
    )



def test_wrong_token_type():

    """
    Verify that an access token cannot
    be used as a refresh token.
    """

    token = create_access_token(
        {
            "sub": "testuser"
        }
    )


    assert verify_token(
        token,
        expected_type="refresh"
    ) is None


    print(
        "   ✅ Wrong token type rejected"
    )



def test_refresh_token_type():

    """
    Verify refresh token behaviour.
    """

    token = create_refresh_token(
        {
            "sub": "testuser"
        }
    )


    assert verify_token(
        token,
        expected_type="refresh"
    ) == "testuser"



    assert verify_token(
        token,
        expected_type="access"
    ) is None


    print(
        "   ✅ Refresh token validation successful"
    )



def test_refresh_token_has_jti():

    """
    Refresh tokens require a unique jti
    because refresh-token rotation and
    reuse detection depend on it.
    """

    token = create_refresh_token(
        {
            "sub": "testuser"
        }
    )


    payload = decode_token_payload(
        token
    )


    assert payload is not None
    assert "jti" in payload
    assert payload["type"] == "refresh"


    print(
        "   ✅ Refresh token contains jti"
    )



def test_expired_token():

    """
    Verify expired tokens are rejected.
    """

    token = jwt.encode(
        {
            "sub": "testuser",
            "type": "access",
            "exp": datetime.now(timezone.utc)
            - timedelta(minutes=1),
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


    assert verify_token(
        token,
        expected_type="access"
    ) is None


    print(
        "   ✅ Expired token rejected"
    )



def test_invalid_signature():

    """
    Verify invalid signatures are rejected.
    """

    token = jwt.encode(
        {
            "sub": "testuser",
            "type": "access",
            "exp": datetime.now(timezone.utc)
            + timedelta(minutes=5),
        },
        "WRONG_SECRET",
        algorithm=ALGORITHM,
    )


    assert verify_token(
        token,
        expected_type="access"
    ) is None


    print(
        "   ✅ Invalid signature rejected"
    )



def test_invalid_token():

    """
    Verify completely invalid JWT strings fail.
    """

    assert verify_token(
        "not.a.real.jwt",
        expected_type="access"
    ) is None


    print(
        "   ✅ Invalid token rejected"
    )



def test_none_token():

    """
    Verify missing token is rejected safely.
    """

    assert verify_token(
        None,
        expected_type="access"
    ) is None


    print(
        "   ✅ Missing token rejected"
    )



# ==========================================================
# RUNNER
# ==========================================================

if __name__ == "__main__":


    print("\n========================================")
    print("JWT VALIDATION TESTS")
    print("========================================")


    test_valid_access_token()
    test_wrong_token_type()
    test_refresh_token_type()
    test_refresh_token_has_jti()
    test_expired_token()
    test_invalid_signature()
    test_invalid_token()
    test_none_token()


    print(
        "\n🎉 ALL JWT TESTS COMPLETED SUCCESSFULLY"
    )