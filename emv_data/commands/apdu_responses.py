from dataclasses import dataclass

@dataclass  
class APDUResponse:
    code: str
    description: str 
    category: str

APDU_RESPONSES = {
    '9000': APDUResponse('9000', 'Success', 'Success'),
    '6A82': APDUResponse('6A82', 'File not found', 'Error'),
    '6985': APDUResponse('6985', 'Conditions not satisfied', 'Error'),
    '6982': APDUResponse('6982', 'Security status not satisfied', 'Error'),
    '6A86': APDUResponse('6A86', 'Incorrect parameters P1-P2', 'Error')
}

def get_apdu_response(code):
    return APDU_RESPONSES.get(code)

def is_success(code):
    return code == '9000'

def is_warning(code):
    response = get_apdu_response(code)
    return response and response.category == 'Warning'

def is_error(code):
    response = get_apdu_response(code)
    return response and response.category == 'Error'

def list_response_codes():
    return list(APDU_RESPONSES.keys())
