def CardConnection(*args, **kwargs):
    class Dummy:
        def transmit(self, apdu):
            return [], 0x90, 0x00
    return Dummy()
