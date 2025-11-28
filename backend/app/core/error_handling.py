"""
Error handling utilities for secure error responses.

Sanitizes error messages to prevent information disclosure
while maintaining useful logging for debugging.
"""

import structlog
from typing import Optional
from fastapi import HTTPException, status

logger = structlog.get_logger(__name__)


class SafeHTTPException(HTTPException):
    """
    HTTPException that logs detailed error internally while 
    returning a sanitized message to the client.
    """
    
    def __init__(
        self, 
        status_code: int,
        detail: str,
        internal_detail: Optional[str] = None,
        log_level: str = "error"
    ):
        """
        Args:
            status_code: HTTP status code
            detail: Safe message to return to client
            internal_detail: Detailed message for logging only
            log_level: Logging level (error, warning, info)
        """
        super().__init__(status_code=status_code, detail=detail)
        
        # Log the full error internally
        log_func = getattr(logger, log_level, logger.error)
        log_func(
            "HTTP exception raised",
            status_code=status_code,
            client_message=detail,
            internal_message=internal_detail or detail
        )


def sanitize_error(
    error: Exception,
    operation: str,
    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
    client_message: Optional[str] = None
) -> HTTPException:
    """
    Create a sanitized HTTP exception from an exception.
    
    Args:
        error: The original exception
        operation: Description of the operation that failed
        status_code: HTTP status code to return
        client_message: Optional custom message for client (defaults to generic message)
        
    Returns:
        HTTPException with sanitized message
    """
    # Log the full error internally
    logger.error(
        f"{operation} failed",
        error_type=type(error).__name__,
        error_message=str(error),
        operation=operation
    )
    
    # Return generic message to client
    safe_message = client_message or f"{operation} failed. Please try again or contact support."
    
    return HTTPException(
        status_code=status_code,
        detail=safe_message
    )


def safe_error_response(
    operation: str,
    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
    include_operation: bool = True
) -> str:
    """
    Generate a safe error message for client response.
    
    Args:
        operation: Description of the operation
        status_code: HTTP status code
        include_operation: Whether to include operation name in message
        
    Returns:
        Safe error message string
    """
    if status_code == status.HTTP_500_INTERNAL_SERVER_ERROR:
        if include_operation:
            return f"{operation} failed. Please try again later."
        return "An internal error occurred. Please try again later."
    elif status_code == status.HTTP_400_BAD_REQUEST:
        return f"Invalid request for {operation}." if include_operation else "Invalid request."
    elif status_code == status.HTTP_403_FORBIDDEN:
        return "You do not have permission to perform this action."
    elif status_code == status.HTTP_404_NOT_FOUND:
        return "The requested resource was not found."
    else:
        return "An error occurred. Please try again."
