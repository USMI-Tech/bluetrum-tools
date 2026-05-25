from bluetrum.crc import ab_crc16


class UARTDownload:
    # special tokens
    SYNC_TOKEN  = b'\xA5\x96\x87\x5A'   # Sync token
    SYNC_RESP   = b'\x5A\x69\x78\xA5'   # Sync response
    RESET_TOKEN = b'\xF5\xA0'           # Communication Reset token

    # response tokens
    RESP_ACK     = 0x1E   # Data packet has been accepted
    RESP_NAK     = 0x2D   # No data available (receive); No space for data (send)
    RESP_NYET    = 0x3C   # Data packet accepted but there is no more space for another one.

    # request tokens
    DATA_TOKEN   = 0x4B   # Data token.
    DATA_REQUEST = 0xB4   # Request for data.
    PING_TOKEN   = 0xC3   # Can we send more data?

    #------------------------------------------

    def __init__(self, port, has_echo=True):
        self.port = port
        self.has_echo = has_echo
        self.comms_reset()

    def port_read(self, size):
        data = self.port.read(size)
        if len(data) < size:
            raise TimeoutError(f'Not enough data has been received from the port (had only {len(data)} bytes)')
        return data

    def port_write(self, data):
        self.port.write(data)
        if self.has_echo:
            # consume the echo back (AB560X/PRAO echoes TX bytes)
            self.port.read(len(data))

    def comms_reset(self):
        self.counter = 0
        self.ping_before_send = False

    def send_reset(self, hard=False):
        if not hard:
            # communication soft-reset
            self.port_write(UARTDownload.RESET_TOKEN)
        else:
            # chip hard-reset
            self.port_write(UARTDownload.RESET_TOKEN + UARTDownload.SYNC_TOKEN)

        # this makes sense
        self.comms_reset()

    def _make_token_packet(self, token):
        # increase the counter
        self.counter = (self.counter + 1) & 0xff
        # make the token packet
        return bytes([token, self.counter])

    def _recv_token_packet(self):
        # receive the token packet
        recv = self.port_read(2)
        # check the counter value
        if recv[1] != self.counter:
            raise ValueError(f'Mismatch in counter value ({recv[1]}) from expected ({self.counter})')
        # return the received token value
        return recv[0]

    def _make_data_payload(self, data):
        return len(data).to_bytes(2, 'little') + data + ab_crc16(data).to_bytes(2, 'little')

    def _recv_data_payload(self):
        # receive data length
        size = int.from_bytes(self.port_read(2), 'little')
        # receive data payload
        data = self.port_read(size)
        # receive data CRC
        crc = int.from_bytes(self.port_read(2), 'little')

        # check the received data CRC
        if ab_crc16(data) != crc:
            raise ValueError('Received data packet CRC mismatch')

        # return the data payload
        return data

    def send_packet(self, data):
        data = self._make_data_payload(data)

        do_ping = self.ping_before_send

        while True:
            if do_ping:
                packet = self._make_token_packet(UARTDownload.PING_TOKEN)
            else:
                packet = self._make_token_packet(UARTDownload.DATA_TOKEN) + data

            tries = 0
            while True:
                self.port_write(packet)

                try:
                    resp = self._recv_token_packet()
                except TimeoutError:
                    if tries > 10:
                        raise TimeoutError("Could not send a data packet.")
                    tries += 1
                else:
                    break

            if do_ping:
                if resp == UARTDownload.RESP_ACK:
                    do_ping = False
                elif resp == UARTDownload.RESP_NAK:
                    pass
                else:
                    raise RuntimeError(f'Ping: Unexpected response token {resp:02X}')
            else:
                if resp == UARTDownload.RESP_ACK:
                    self.ping_before_send = False
                    return
                elif resp == UARTDownload.RESP_NYET:
                    self.ping_before_send = True
                    return
                elif resp == UARTDownload.RESP_NAK:
                    do_ping = True
                else:
                    raise RuntimeError(f'Tx: Unexpected response token {resp:02X}')

    def recv_packet(self):
        request = self._make_token_packet(UARTDownload.DATA_REQUEST)

        tries = 0

        while True:
            self.port_write(request)

            try:
                resp = self._recv_token_packet()
            except TimeoutError:
                if tries > 10:
                    raise TimeoutError("Could not request a data packet.")
                tries += 1
                continue
            else:
                tries = 0

            if resp == UARTDownload.DATA_TOKEN:
                try:
                    data = self._recv_data_payload()
                except Exception:
                    pass
                else:
                    return data
            elif resp == UARTDownload.RESP_NAK:
                continue
            else:
                raise RuntimeError(f'Rx: Unexpected response token {resp:02X}')

            tries += 1
