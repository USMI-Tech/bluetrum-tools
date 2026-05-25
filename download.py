from bluetrum.cipher import ab_calckey
from bluetrum.utils import *

import struct
import argparse

from base64 import b64decode
from tqdm import tqdm

###############################################################################

try:
    from serial import Serial
    from bluetrum.dl.uart import UARTDownload
    have_uart = True
except ImportError:
    have_uart = False

try:
    from scsiio import SCSIDev
    have_scsi = True
except ImportError:
    have_scsi = False

if not have_uart and not have_scsi:
    print('No available ways to communicate with the hardware.')
    print('Install pyserial for UART or rip "scsiio" from jl-uboot-tool for USB MSC.')
    exit(1)

###############################################################################

ap = argparse.ArgumentParser(description='Tool to communicate with the bootloader in the Bluetrum chips.')

if have_uart:
    ap.add_argument('--init-baud', type=int, default=115200,
                    help='Initial baudrate (default: %(default)d baud)')
    ap.add_argument('--baud', type=int, default=921600,
                    help='Baudrate to use (default: %(default)d baud)')
    ap.add_argument('--port',
                    help='Serial port to use for UART bootloader')
    ap.add_argument('--no-echo', action='store_true', default=False,
                    help='Disable echo (for CRWN/AB530X chips)')

if have_scsi:
    ap.add_argument('--mscdev',
                    help='USB MSC (SCSI) device to use for USB bootloader')

ap.add_argument('-r', '--reboot', action='store_true',
                help='Reboot the chip after completion')
ap.add_argument('--debug', action='store_true', default=False,
                help='Enable extra diagnostic output')

actsp = ap.add_subparsers(dest='action')

asp_erase = actsp.add_parser('erase', help='Erase one or more flash areas')
asp_erase.add_argument('areas', metavar='address size', nargs='+',
                       help='Erase <size> bytes at <address>.'
                            ' If <size> is 0, assumed to be whole flash.')

asp_read = actsp.add_parser('read', help='Read the flash into the file')
asp_read.add_argument('areas', metavar='address size file', nargs='+',
                      help='Read <size> bytes from <address> into <file>.'
                           ' If <size> is 0, assumed to be whole flash.')

asp_write = actsp.add_parser('write', help='Write the file into flash')
asp_write.add_argument('areas', metavar='address file', nargs='+',
                       help='Write <file> starting at <address>.')

args = ap.parse_args()

###############################################################################

# PRAO (AB560x) — hand-built blob; bytes [4..23] are reserved for
# chipid / iface / blocksize injection at load time.
dl_blob = b64decode(
    "bwBABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJcCAACTgsL/"
    "g6ICAGOeAgJhEQbAKsKXAgAAk4IiXBcDAAATA6NbY9ZiACOgAgCRAt2/7wBAFpcCAACTgmL8"
    "g6ICAIJAEkUhAYKCAAAYUTlxBt46xhMHACA6yBhBg0bVAoNHdQIYR8IGIwTxADrKWEGDR4UC"
    "GEejBPEAg1dFAjrMSWcTB8cUOs5JZxMHZxI60ANHxQIq1CMV8QBiB1WPg0b1AlWPg0blAigA"
    "ogZVjzrSN3diABMHVzc61rEp8lAhYYKAQREmwgRRIsQGxshALoTv0JZ3yEDv0HZ3bd2yQCKF"
    "IkSSREEBgoBBESbCBFEixAbGiEAuhO/QNnWIQO/QFnVt3bJAIoUiRJJEQQGCgG/QdnMBES6F"
    "Bs4uxu/QdnLyQDJFBWGCgFhBOXEG3oNHBwBUXSME8QCDR1cANsY6zJMGACBJZzbIEwdnFxRB"
    "Os5JZxMHJxc2yjrQg0aVAANHhQCjBPEAwgZiB1WPg0a1ADxBKtRVj4NGpQAoACMV8QCiBlWP"
    "OtI3Z3J0EwdXFzrWYSbyUCFhgoBBEQbGrS7JZ5OHRwDYR7dncnSTh1cXYxz3AMlnSWeTh6cY"
    "IyD3BrJAAUVBAYKAt3diAJOHVzfjGPf+yWdJZ5OHBwvFtwEAfRV1/YKAkweACphDkxb3AOPb"
    "Bv5BZ9jHgoCTB4AKmEM9m5jDyMPFt0ERIsQTBIAKHEAGxpPnBwEcwJMH8A9cwNk3SECyQCJE"
    "E3X1D0EBgoCTB4AKmEM9m5jDyMuMy2W3kweACphDE2cHAZjDyMuMy1m/IyQACoVHYxH1BJMH"
    "AHARR5jD2Edtm9jHJUeYw9hHWZvYx0FHIy7gANhLE2cnA9jL2EcTd/f82MfYTxNnJwDYz9hH"
    "E2cnANjHkweACozHmEMTZxcAmMMTB8A0HEPpmxzDgoCDJ8ABQUeT9wcPY5XnAJFHIyLwcIKA"
    "gyfAAUFHk/cHD2OV5wCRRyMg8HCCgEERBsbBPxlFCT+yQEEB8b8BEQbOIswuxiqEbT8TBfAJ"
    "7T2yRSKFLT9iRPJABWF1vwERBs4uxiLMKoRpPxMFsATpPQFF2T0BRck9AUX5NQFF6TWyRSKF"
    "KTdiRPJABWFxtwERBs4yxiLMJsoqhK6EnTcTBaAFXTUTVQRBE3X1D3E9E1WEQBN19Q9JPRN1"
    "9A9xNQFFYTWyRSaF4TViRPJA0kQFYaG3AREGzjLGIswmyiqEroQNNy1FlTUTVQRBE3X1D6k9"
    "E1WEQBN19Q+BPRN19A+pNQFFmTWyRSaFWTViRPJA0kQFYRm3AREGziLMJsoyxq6EKoTFNQlF"
    "DTUTVQRBE3X1DyE9E1WEQBN19Q85NRN19A8hNbJFJoUlPWJE8kDSRAVh4bVBEQbGIsQqhGU1"
    "EwUAAuUzE1UEQRN19Q/5OxNVhEATdfUP0TsTdfQP+TMiRLJAQQFZvUERBsYixCqEnT0TBYAN"
    "XTsTVQRBE3X1D3UzE1WEQBN19Q9NMxN19A9xOyJEskBBAZW1QREGxqE1FUVpM1k7BYl1/bJA"
    "QQG5tQERaACNRQbOrTWDR8EAA0fRAANF4QDyQMIHIgfZj12NBWGCgM21AREmykrITsZSxAbO"
    "Iswqia6JsoQTCgAQY0qQAPJAYkTSREJJskkiSgVhgoATdPkPMwSKQGPThAAmhAk1zoVKhSKG"
    "xTWimb0/IpmBjPG3AREizCrGBs4uhNUzMkUByIVHYwj0AGJE8kAFYam/1T3dvw03zb+CgAER"
    "IswGzibKSshOxoNHBQAJRyqEY4jnBmNl9wKV70RF79B2MIVFiMAuhTkzJT/IwMFFE4WEAMEz"
    "XEjhRSKFgpchoA1HY4bnBvJAYkTSREJJskkBRQVhgoCDKUUAA1klAONUIP8ERGNTmQDKhExE"
    "ToUmhuU7XEimhSKFgpczCZlAppn5v4MpRQADWSUA414g+wREY1OZAMqEHEymhSKFgpcMSE6F"
    "JobVNTMJmUCmmfm/g0UVAEhBhYGFiZPFFQApP2G3"
)

# CRWN (AB530x) — decrypted uartdown-001.dll.
# Bytes [4..23] contain live UART helper functions used by the blob itself;
# do NOT overwrite them at load time (unlike the PRAO blob).
dl_blob_crwn = b64decode(
    "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"
    "AAAAAAAAAAAAAAAA"
)

###############################################################################

class BlCmd:
    IFACE_PARAM     = 0x50
    AUTHORIZE       = 0x55
    MEM_WRITE       = 0x57
    SET_CMD_HANDLER = 0x58
    GET_INFO        = 0x5A
    REBOOT          = 0x5E


class NitDlCmd:
    """Command codes for PRAO (AB560x) blob."""
    INIT      = 0x00
    DEV_READ  = 0x01
    DEV_WRITE = 0x02
    DEV_ERASE = 0x03


class NitDlCmdCRWN:
    """Command codes for CRWN (AB530x) blob (uartdown-001.dll)."""
    INIT      = 0x00   # returns 4 bytes: [status, ?, density, ?]
    DEV_READ  = 0x28   # arg1=addr  arg3=n_blocks(x512B)  recv=n_blocks*512
    DEV_WRITE = 0x2a   # arg1=addr  arg3=1  send=512B  recv=1  (one block)
    DEV_ERASE = 0x2f   # arg1=addr  arg3=1  recv=512   (one 64K block)
    GET_INFO  = 0x25   # recv=16 → bytes [0xC..0xE] = JEDEC device ID


def make_cb(cmd, arg1=0, arg2=0, arg3=0):
    return struct.pack('>BIBH', cmd, arg1, arg2, arg3)


def patch_crwn_blob(blob_bytes):
    """
    Fix six bugs in the CRWN blob (uartdown-001.dll).

    Each patch replaces one wrong instruction with the correct one.
    All offsets are relative to the start of the decrypted blob binary.

    P3  READ  0x0B3C  BLTU x21,x18      → NOP
        Removes a hardcoded address ceiling (0x1E00) that caused the READ
        loop to return zeros for any flash address >= 0x1E00.

    P4a INIT  0x04D6  addi a5,a5,-0x1C4 → addi a5,a5,+0x2D6
        In the flash-detection fallback path, INIT stores a do-nothing stub
        at all iface function slots. This patch redirects the iface[0x10]
        store to the real flash_erase function (VA 0x132D6).

    P4b INIT  0x04EA  addi a5,a5,-0x1C4 → addi a5,a5,+0x266
        Same fallback path — redirects the iface[0x0C] store to the real
        flash_write function (VA 0x13266).

    P5  ERASE 0x0C40  c.beqz a5,+70    → c.nop
        A flag check (iface[0x18].bit3) gates the DMA erase path. The flag
        is never set on this chip variant so the handler always branched to
        a no-op. This patch makes it always take the DMA path.

    P6  ERASE 0x0C42  lw a5,8(s4)      → lw a5,0x10(s4)
        The handler was loading iface[8] (flash_read pointer) into a5 and
        calling it as if it were flash_erase. Changed load offset from 8 to
        0x10 so it loads iface[0x10] (flash_erase pointer) instead.

    P7  WRITE 0x0BB8  c.beqz a5,+14    → c.nop
        A bit1 guard inside the per-block success path skipped the
        flash_write call when the flag was clear. The flag is never set by
        INIT on this chip. Removed so flash_write is always called.

    P8  ERASE 0x0C4E  addi a0,s8,0x2B8 → addi a0,zero,0xD8
        The handler passed a buffer pointer as a0 to flash_erase. The low
        byte (0xB8) is not a valid SPI opcode so the flash ignored every
        erase command. Replaced with the correct 64K block-erase opcode
        (0xD8).
    """
    b = bytearray(blob_bytes)

    def patch(off, expected, replacement, name):
        exp = bytes(expected)
        assert b[off:off+len(exp)] == exp, (
            f'CRWN blob {name}: expected {exp.hex()} at {off:#06x}, '
            f'got {b[off:off+len(exp)].hex()}')
        b[off:off+len(replacement)] = bytes(replacement)

    patch(0x0b3c, [0x63,0xee,0x2a,0x01], [0x13,0x00,0x00,0x00], 'P3')
    patch(0x04d6, [0x93,0x87,0xc7,0xe3], [0x93,0x87,0x67,0x2d], 'P4a')
    patch(0x04ea, [0x93,0x87,0xc7,0xe3], [0x93,0x87,0x67,0x26], 'P4b')
    patch(0x0c40, [0xb9,0xc3],           [0x01,0x00],           'P5')
    patch(0x0c42, [0x83,0x27,0x8a,0x00], [0x83,0x27,0x0a,0x01], 'P6')
    patch(0x0bb8, [0x99,0xc7],           [0x01,0x00],           'P7')
    patch(0x0c4e, [0x13,0x05,0x8c,0x2b], [0x13,0x05,0x80,0x0d], 'P8')

    return bytes(b)


def do_the_stuff(execcmd, blocksize, iface):
    # -------------------------------------------------------------------------
    # Bootloader handshake
    # -------------------------------------------------------------------------
    resp = execcmd(make_cb(BlCmd.GET_INFO, arg1=0x5259414E, arg3=0x67ca), recv=24)
    chipid, loadaddr, commskey, _ = struct.unpack('>12sIII', resp)
    print(f' Chip ID:       {chipid}')
    print(f' Load address:  ${loadaddr:08X}')
    print(f' Init. commkey: ${commskey:08X}')

    resp = execcmd(make_cb(BlCmd.AUTHORIZE, arg1=ab_calckey(commskey)), recv=4)
    commskey, = struct.unpack('>I', resp)
    print(f' New commkey:   ${commskey:08X}')

    if iface == 'uart' and args.baud != args.init_baud:
        print(f'Changing baudrate to {args.baud} baud...')
        execcmd(make_cb(BlCmd.IFACE_PARAM, arg2=0xf0), recv=2)
        execcmd(make_cb(BlCmd.IFACE_PARAM, arg1=args.baud, arg2=0x02),
                recv=2, switch_baud=args.baud)

    # -------------------------------------------------------------------------
    # Load and patch blob
    # -------------------------------------------------------------------------
    is_crwn = b'CRWN' in chipid

    if is_crwn:
        Cmd       = NitDlCmdCRWN
        blob_data = patch_crwn_blob(dl_blob_crwn)
    else:
        Cmd       = NitDlCmd
        blob_data = dl_blob

    data = bytearray(blob_data) + b'\x00' * align_by(len(blob_data), blocksize)
    if not is_crwn:
        struct.pack_into('<12s4sI', data, 4, chipid, iface.encode(), blocksize)

    execcmd(make_cb(BlCmd.MEM_WRITE, arg1=loadaddr,
                    arg3=(len(data) // blocksize)), send=data)
    execcmd(make_cb(BlCmd.SET_CMD_HANDLER, arg1=loadaddr))

    # -------------------------------------------------------------------------
    # Blob init — detect flash, print chip info
    # -------------------------------------------------------------------------
    if is_crwn:
        init_resp = execcmd(make_cb(Cmd.INIT, arg1=0), recv=4)
        density   = init_resp[2] or init_resp[1]
        fsize     = (1 << (density + 6)) if density else None

        # Codekey is derived by INIT from flash[0x1FC..0x1FD] using:
        #   val     = uint16_LE( flash[0x1FC] )
        #   codekey = (~val & 0xFFFF) ^ (val << 16) ^ 0x594B5048
        # This mirrors what the chip writes to SFR 0x348 (flash DMA key).
        raw_ck  = execcmd(make_cb(Cmd.DEV_READ, arg1=0x1fc, arg3=1), recv=512)
        val     = struct.unpack_from('<H', raw_ck, 0)[0]
        codekey = ((~val & 0xffff) ^ (val << 16) ^ 0x594b5048) & 0xffffffff

        # CMD 0x25 reads the JEDEC device ID via ROM 0x80064 (opcode 0x9F).
        # The blob returns it big-endian in response bytes [0xC..0xF].
        # Bytes [0x0..0x7] of the response buffer may contain the 64-bit Unique
        # ID (opcode 0x4B) if the AB530x ROM fills it — this depends on the ROM
        # revision.  We extract it opportunistically and skip if all-zero.
        try:
            resp25   = execcmd(make_cb(Cmd.GET_INFO), recv=16)
            flash_id = struct.unpack_from('>I', resp25, 0xc)[0] & 0xffffff
            flash_uid_raw = resp25[0:8]
            flash_uid = flash_uid_raw if any(b != 0 for b in flash_uid_raw) else None
        except Exception:
            flash_id  = 0
            flash_uid = None

        print(f'- Code key: >>>> {codekey:08X} <<<<')
        if flash_id:
            print(f'- Flash device ID: {flash_id:06X}')
        if flash_uid:
            print(f'- Flash unique ID: {flash_uid.hex()}')
        if fsize:
            print(f'- Flash size: {fsize} bytes')
        else:
            print('- Flash size: unknown')

    else:
        codekey, flashid, flashuid = struct.unpack(
            'II16s', execcmd(make_cb(Cmd.INIT), recv=48))
        density = flashid & 0xff
        fsize   = (1 << density) if 0x10 <= density <= 0x18 else None

        print(f'- Code key: >>>> {codekey:08X} <<<<')
        print(f'- Flash device ID: {flashid:06X}')
        print(f'- Flash unique ID: {flashuid.hex()}')
        if fsize:
            print(f'- Flash size: {fsize} bytes')
        else:
            print('- Flash size: unknown')

    # -------------------------------------------------------------------------
    # Flash operations
    # -------------------------------------------------------------------------

    def do_dev_erase(addr, size):
        """Erase a flash region, choosing 64K or 4K blocks automatically."""
        saddr = addr & ~0xFFF
        eaddr = (addr + size + 0xFFF) & ~0xFFF

        tq = tqdm(desc='Erasing', total=(eaddr - saddr),
                  unit='B', unit_divisor=1024, unit_scale=True)
        try:
            cur = saddr
            while cur < eaddr:
                aligned_64k = (cur & 0xFFFF) == 0
                space_64k   = (eaddr - cur) >= 0x10000

                if is_crwn:
                    # CMD 0x2F / arg3=1: blob sends one SPI erase command (0xD8,
                    # 64K block erase) via flash_erase and returns immediately —
                    # without polling BUSY.  We then issue a DEV_READ (0x28) for
                    # one 512-byte block: the ROM flash_read driver waits for the
                    # flash BUSY bit (WIP, STATUS[0]) to clear before asserting
                    # CS and sending the SPI READ command, so this dummy read
                    # naturally blocks until the erase is complete.
                    execcmd(make_cb(Cmd.DEV_ERASE, arg1=cur,
                                    arg2=0x01, arg3=1), recv=512)
                    execcmd(make_cb(Cmd.DEV_READ, arg1=0, arg3=1), recv=512)
                    cur += 0x10000
                    tq.update(0x10000)
                else:
                    if aligned_64k and space_64k:
                        blksize, flags = 0x10000, 0x00
                    else:
                        blksize, flags = 0x1000, 0x02
                    execcmd(make_cb(Cmd.DEV_ERASE, arg1=cur, arg2=flags))
                    cur += blksize
                    tq.update(blksize)
        finally:
            tq.close()

    # ------------------------------------------------------------------

    try:
        if args.action == 'erase':
            for i in range(0, len(args.areas), 2):
                addr = int(args.areas[i],     0)
                size = int(args.areas[i + 1], 0)
                if size <= 0:
                    if fsize is None: raise RuntimeError('Unknown flash size')
                    size = fsize - addr
                do_dev_erase(addr, size)

        elif args.action == 'read':
            for i in range(0, len(args.areas), 3):
                addr = int(args.areas[i],     0)
                size = int(args.areas[i + 1], 0)
                path = args.areas[i + 2]
                if size <= 0:
                    if fsize is None: raise RuntimeError('Unknown flash size')
                    size = fsize - addr

                io_size = min(0x8000, max(blocksize,
                                          align_to(size // 100, blocksize)))
                print(f'Reading {size} bytes from @{addr:06X} into "{path}"...')

                tq = tqdm(desc='Reading', total=size,
                          unit='B', unit_divisor=1024, unit_scale=True)
                try:
                    with open(path, 'wb') as f:
                        done = 0
                        while done < size:
                            n     = min(io_size, size - done)
                            _a3   = (n // 512) if is_crwn else n
                            f.write(execcmd(
                                make_cb(Cmd.DEV_READ, arg1=addr + done, arg3=_a3),
                                recv=n))
                            tq.update(n)
                            done += n
                finally:
                    tq.close()

        elif args.action == 'write':
            for i in range(0, len(args.areas), 2):
                addr = int(args.areas[i], 0)
                path = args.areas[i + 1]

                with open(path, 'rb') as f:
                    raw = f.read()

                BLOCK = 512
                if len(raw) % BLOCK:
                    raw += b'\xff' * (BLOCK - len(raw) % BLOCK)
                n_blocks = len(raw) // BLOCK

                print(f'Writing {len(raw)} bytes to @{addr:06X} from "{path}"...')
                do_dev_erase(addr, len(raw))

                if is_crwn:
                    # CMD 0x2A — CRWN write, one 512-byte block per call.
                    #
                    # Flow for each block:
                    #   send_packet(CB)   — BL ACKs immediately, then calls blob.
                    #                       Blob enters ROM recv() and waits for
                    #                       the data packet.
                    #   send_packet(data) — BL's UART ISR independently receives
                    #                       this framed 512-byte packet, ACKs it,
                    #                       and stores the payload in the buffer
                    #                       pointed to by s0 (= iface[4], the CB
                    #                       pointer set at blob entry).  ROM recv()
                    #                       reads from that same buffer and returns
                    #                       512.
                    #   recv=1            — drains the 1-byte blob response, keeps
                    #                       BL's TX queue empty and the packet
                    #                       counter in sync for the next block.
                    #
                    # arg2=0x00 keeps a3=0 inside the blob so flash_write programs
                    # flash with DMA key=0 (no encryption).  arg2=0x02 would load
                    # iface[4] as the DMA key and silently corrupt every byte.
                    tq = tqdm(desc='Writing', total=len(raw),
                              unit='B', unit_divisor=1024, unit_scale=True)
                    try:
                        for blk in range(n_blocks):
                            cb = make_cb(Cmd.DEV_WRITE,
                                         arg1=addr + blk * BLOCK,
                                         arg2=0x00, arg3=1)
                            execcmd(cb,
                                    send=raw[blk * BLOCK : (blk + 1) * BLOCK],
                                    recv=1)
                            tq.update(BLOCK)
                    finally:
                        tq.close()

                else:
                    io_size = min(0x8000, max(blocksize,
                                              align_to(len(raw) // 100, blocksize)))
                    tq = tqdm(desc='Writing', total=len(raw),
                              unit='B', unit_divisor=1024, unit_scale=True)
                    try:
                        done = 0
                        while done < len(raw):
                            block = raw[done:done + io_size]
                            execcmd(make_cb(Cmd.DEV_WRITE,
                                            arg1=addr + done, arg3=len(block)),
                                    send=block)
                            tq.update(len(block))
                            done += len(block)
                    finally:
                        tq.close()

    except KeyboardInterrupt:
        print('interrupted!')
    except Exception as e:
        print('failed:', e)
        raise

    if args.reboot:
        execcmd(make_cb(BlCmd.REBOOT))

###############################################################################

if have_uart and args.port is not None:
    with Serial(args.port) as port:
        udl = UARTDownload(port, has_echo=not args.no_echo)

        print('Trying to synchronize.', end='')
        port.timeout = .01

        try:
            done = False
            num  = 0
            turn = 0
            while not done:
                if num < 10:
                    udl.port.reset_input_buffer()
                    udl.port.write(UARTDownload.SYNC_TOKEN)
                    while not done:
                        recv = udl.port.read(4)
                        if recv == b'': break
                        if recv == UARTDownload.SYNC_RESP:
                            done = True
                    num += 1
                else:
                    print('.', end='', flush=True)
                    if turn == 0:
                        udl.port.baudrate = args.init_baud
                        udl.send_reset(True)
                        turn = 1
                    else:
                        udl.port.baudrate = args.baud
                        udl.send_reset(True)
                        udl.port.baudrate = args.init_baud
                        turn = 0
                    num = 0
        except Exception as e:
            print(' failed:')
            raise e
        else:
            print(' done.')

        port.reset_input_buffer()
        port.timeout = .1

        def execcmd(cb, send=None, recv=None, max_io=512, switch_baud=None):
            udl.send_packet(cb)

            if switch_baud is not None:
                port.baudrate = switch_baud

            if send is not None:
                sent = 0
                while sent < len(send):
                    n = min(len(send) - sent, max_io)
                    udl.send_packet(send[sent:sent + n])
                    sent += n

            elif recv is not None:
                data = b''
                while len(data) < recv:
                    n     = min(recv - len(data), max_io)
                    block = udl.recv_packet()
                    data += block
                    if len(block) != n:
                        break
                return data

        do_the_stuff(execcmd, 512, 'uart')

elif have_scsi and args.mscdev is not None:
    with SCSIDev(args.mscdev) as dev:
        def execcmd(cb, send=None, recv=None, **_):
            if recv is not None:
                recv = bytearray(recv)
            if send is not None and not isinstance(send, bytes):
                send = bytes(send)
            dev.execute(b'\xfc' + cb, send, recv)
            return recv

        do_the_stuff(execcmd, 512, 'usb')

else:
    print('No device specified:')
    if have_uart: print(' - UART: specify the serial port via --port')
    if have_scsi: print(' - USB MSC: specify the device via --mscdev')
