class ContactlessFrontend:
    def __init__(self, *args, **kwargs):
        pass

    def close(self):
        pass

    def connect(self, *args, **kwargs):
        class Tag:
            identifier = b"\xDE\xAD\xBE\xEF"
        return Tag()
