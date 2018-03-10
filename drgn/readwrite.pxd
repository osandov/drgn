from cpython.buffer cimport Py_buffer
from libc.stdint cimport int8_t, int16_t, int32_t, int64_t, uint8_t, uint16_t, uint32_t, uint64_t
from libc.string cimport memchr, memcpy


cdef extern from "Python.h":

    cdef Py_ssize_t PY_SSIZE_T_MAX
    str PyUnicode_FromStringAndSize(const char *u, Py_ssize_t size)
    bytes PyBytes_FromStringAndSize(const char *v, Py_ssize_t size)


cdef inline check_bounds(Py_buffer *buffer, Py_ssize_t offset, Py_ssize_t size):
    if buffer.len < size or offset > buffer.len - size:
        raise EOFError()


cdef inline read_buffer(Py_buffer *buffer, Py_ssize_t *offset, void *ret,
                        Py_ssize_t size):
    check_bounds(buffer, offset[0], size)
    memcpy(ret, <const char *>buffer.buf + offset[0], size)
    offset[0] += size


cdef inline bytes read_bytes(Py_buffer *buffer, Py_ssize_t *offset,
                             Py_ssize_t size):
    check_bounds(buffer, offset[0], size)
    cdef bytes ret = PyBytes_FromStringAndSize(<const char *>buffer.buf + offset[0], size)
    offset[0] += size
    return ret


cdef inline str read_str(Py_buffer *buffer, Py_ssize_t *offset):
    if offset[0] >= buffer.len:
        raise EOFError()

    cdef const char *p = <const char *>buffer.buf + offset[0]
    cdef const char *nul = <const char *>memchr(p, 0, buffer.len - offset[0])
    if nul == NULL:
        raise ValueError('unterminated string')
    offset[0] += (nul - p) + 1
    return PyUnicode_FromStringAndSize(p, nul - p)


cdef inline Py_ssize_t read_strlen(Py_buffer *buffer, Py_ssize_t *offset) except -1:
    if offset[0] >= buffer.len:
        raise EOFError()

    cdef const char *p = <const char *>buffer.buf + offset[0]
    cdef const char *nul = <const char *>memchr(p, 0, buffer.len - offset[0])
    if nul == NULL:
        raise ValueError('unterminated string')
    cdef Py_ssize_t ret = nul - p
    offset[0] += ret + 1
    return ret


cdef inline read_s8(Py_buffer *buffer, Py_ssize_t *offset, int8_t *ret):
    check_bounds(buffer, offset[0], sizeof(int8_t))
    ret[0] = (<const int8_t *>(<const char *>buffer.buf + offset[0]))[0]
    offset[0] += sizeof(int8_t)


cdef inline read_s64(Py_buffer *buffer, Py_ssize_t *offset, int64_t *ret):
    check_bounds(buffer, offset[0], sizeof(int64_t))
    ret[0] = (<const int64_t *>(<const char *>buffer.buf + offset[0]))[0]
    offset[0] += sizeof(int64_t)


cdef inline read_u8(Py_buffer *buffer, Py_ssize_t *offset, uint8_t *ret):
    check_bounds(buffer, offset[0], sizeof(uint8_t))
    ret[0] = (<const uint8_t *>(<const char *>buffer.buf + offset[0]))[0]
    offset[0] += sizeof(uint8_t)


cdef inline read_u16(Py_buffer *buffer, Py_ssize_t *offset, uint16_t *ret):
    check_bounds(buffer, offset[0], sizeof(uint16_t))
    ret[0] = (<const uint16_t *>(<const char *>buffer.buf + offset[0]))[0]
    offset[0] += sizeof(uint16_t)


cdef inline read_u32(Py_buffer *buffer, Py_ssize_t *offset, uint32_t *ret):
    check_bounds(buffer, offset[0], sizeof(uint32_t))
    ret[0] = (<const uint32_t *>(<const char *>buffer.buf + offset[0]))[0]
    offset[0] += sizeof(uint32_t)


cdef inline read_u64(Py_buffer *buffer, Py_ssize_t *offset, uint64_t *ret):
    check_bounds(buffer, offset[0], sizeof(uint64_t))
    ret[0] = (<const uint64_t *>(<const char *>buffer.buf + offset[0]))[0]
    offset[0] += sizeof(uint64_t)


cdef inline read_u8_into_u64(Py_buffer *buffer, Py_ssize_t *offset, uint64_t *ret):
    check_bounds(buffer, offset[0], sizeof(uint8_t))
    ret[0] = (<const uint8_t *>(<const char *>buffer.buf + offset[0]))[0]
    offset[0] += sizeof(uint8_t)


cdef inline read_u16_into_u64(Py_buffer *buffer, Py_ssize_t *offset, uint64_t *ret):
    check_bounds(buffer, offset[0], sizeof(uint16_t))
    ret[0] = (<const uint16_t *>(<const char *>buffer.buf + offset[0]))[0]
    offset[0] += sizeof(uint16_t)


cdef inline read_u32_into_u64(Py_buffer *buffer, Py_ssize_t *offset, uint64_t *ret):
    check_bounds(buffer, offset[0], sizeof(uint32_t))
    ret[0] = (<const uint32_t *>(<const char *>buffer.buf + offset[0]))[0]
    offset[0] += sizeof(uint32_t)


cdef inline read_u8_into_ssize_t(Py_buffer *buffer, Py_ssize_t *offset,
                                 Py_ssize_t *ret):
    check_bounds(buffer, offset[0], sizeof(uint8_t))
    ret[0] = (<const uint8_t *>(<const char *>buffer.buf + offset[0]))[0]
    offset[0] += sizeof(uint8_t)


cdef inline read_u16_into_ssize_t(Py_buffer *buffer, Py_ssize_t *offset,
                                  Py_ssize_t *ret):
    check_bounds(buffer, offset[0], sizeof(uint16_t))
    ret[0] = (<const uint16_t *>(<const char *>buffer.buf + offset[0]))[0]
    offset[0] += sizeof(uint16_t)


cdef inline read_u32_into_ssize_t(Py_buffer *buffer, Py_ssize_t *offset,
                                  Py_ssize_t *ret):
    check_bounds(buffer, offset[0], sizeof(uint32_t))
    ret[0] = (<const uint32_t *>(<const char *>buffer.buf + offset[0]))[0]
    offset[0] += sizeof(uint32_t)

cdef inline write_u32(Py_buffer *buffer, Py_ssize_t offset, uint32_t value):
    check_bounds(buffer, offset, sizeof(uint32_t))
    (<uint32_t*>(buffer.buf + offset))[0] = value

cdef inline write_u64(Py_buffer *buffer, Py_ssize_t offset, uint64_t value):
    check_bounds(buffer, offset, sizeof(uint64_t))
    (<uint64_t*>(buffer.buf + offset))[0] = value
