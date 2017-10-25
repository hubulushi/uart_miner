/*
 * c-periphery
 * https://github.com/vsergeev/c-periphery
 * License: MIT
 */

#ifndef _PERIPHERY_SERIAL_H
#define _PERIPHERY_SERIAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

enum serial_error_code {
    SERIAL_ERROR_ARG            = -1, /* Invalid arguments */
    SERIAL_ERROR_OPEN           = -2, /* Opening serial port */
    SERIAL_ERROR_QUERY          = -3, /* Getting serial port attributes */
    SERIAL_ERROR_IO             = -5, /* Reading/writing serial port */
    SERIAL_ERROR_CONFIGURE      = -6, /* Setting serial port attributes */
    SERIAL_ERROR_CLOSE          = -7, /* Closing serial port */
};

typedef struct serial_handle {
    int fd;
    uint8_t chip_nums;
    struct {
        int c_errno;
        char errmsg[96];
    } error;
} serial_t;

typedef enum serial_parity {
    PARITY_NONE,
    PARITY_ODD,
    PARITY_EVEN,
    PARITY_SPACE,
    PARITY_MARK,
} serial_parity_t;

/* Primary Functions */
/**
 * Open the tty device at the specified path (e.g. "/dev/ttyUSB0"), with the specified baudrate, and the defaults
 * of 8 data bits, no parity, 1 stop bit, software flow control (xonxoff) off, hardware flow control (rtscts) off.
 * serial should be a valid pointer to an allocated Serial handle structure.
 * Returns 0 on success, or a negative Serial error code on failure.
 *
 * @param serial
 * @param path
 * @param baudrate
 * @return
 */
int serial_open(serial_t *serial, const char *path, uint32_t baudrate);

/**
 * Open the tty device at the specified path (e.g. "/dev/ttyUSB0"), with the specified baudrate, and the defaults
 * of 8 data bits, no parity, 1 stop bit, software flow control (xonxoff) off, hardware flow control (rtscts) off.
 * serial should be a valid pointer to an allocated Serial handle structure.
 * Returns 0 on success, or a negative Serial error code on failure.
 *
 * @param serial
 * @param path
 * @param baudrate
 * @param databits
 * @param parity
 * @param stopbits
 * @param xonxoff
 * @param rtscts
 * @return
 */
int serial_open_advanced(serial_t *serial, const char *path, uint32_t baudrate, unsigned int databits, serial_parity_t parity, unsigned int stopbits, bool xonxoff, bool rtscts);

/**
 * Read up to len number of bytes from the serial port into the buf buffer with the specified millisecond timeout.
 * A 0 timeout can be specified for a non-blocking read. A negative timeout can be specified for a blocking read
 * that will read until all of the requested number of bytes are read. A positive timeout in milliseconds can be
 * specified for a blocking read with timeout.
 * serial should be a valid pointer to a Serial handle opened with serial_open() or serial_open_advanced().
 * timeout_ms can be positive for a timeout in milliseconds, 0 for a non-blocking read, or a negative number for
 * a blocking read.
 * Returns the number of bytes read on success, 0 on timeout, or a negative Serial error code on failure.
 *
 * @param serial
 * @param buf
 * @param len
 * @param timeout_ms
 * @return
 */
int serial_read(serial_t *serial, uint8_t *buf, size_t len, int timeout_ms);

/**
 * Write len number of bytes from the buf buffer to the serial port.
 * serial should be a valid pointer to a Serial handle opened with serial_open() or serial_open_advanced().
 * Returns the number of bytes written on success, or a negative Serial error code on failure.
 * @param serial
 * @param buf
 * @param len
 * @return
 */
int serial_write(serial_t *serial, const uint8_t *buf, size_t len);

/**
 * Flush the write buffer of the serial port (i.e. force its write immediately).
 * serial should be a valid pointer to a Serial handle opened with serial_open() or serial_open_advanced().
 * Returns 0 on success, or a negative Serial error code on failure.
 * @param serial
 * @return
 */
int serial_flush(serial_t *serial);

/**
 * Query the number of bytes waiting to be read from the serial port.
 * serial should be a valid pointer to a Serial handle opened with serial_open() or serial_open_advanced().
 * Returns 0 on success, or a negative Serial error code on failure.
 * @param serial
 * @param count
 * @return
 */
int serial_input_waiting(serial_t *serial, unsigned int *count);

/**
 * Query the number of bytes waiting to be written to the serial port.
 * serial should be a valid pointer to a Serial handle opened with serial_open() or serial_open_advanced().
 * Returns 0 on success, or a negative Serial error code on failure.
 * @param serial
 * @param count
 * @return
 */
int serial_output_waiting(serial_t *serial, unsigned int *count);

/**
 * Poll for data available for reading from the serial port.
 * serial should be a valid pointer to a Serial handle opened with serial_open() or serial_open_advanced().
 * timeout_ms can be positive for a timeout in milliseconds, 0 for a non-blocking poll, or a negative number
 * for a blocking poll.
 * Returns 1 on success (data available for reading), 0 on timeout, or a negative Serial error code on failure.
 * @param serial
 * @param timeout_ms
 * @return
 */
int serial_poll(serial_t *serial, int timeout_ms);

/**
 * Close the tty device.
 * serial should be a valid pointer to a Serial handle opened with serial_open() or serial_open_advanced().
 * Returns 0 on success, or a negative Serial error code on failure.
 * @param serial
 * @return
 */
int serial_close(serial_t *serial);

/**
 ***** Getter
 * Query the baudrate, data bits, parity, stop bits, software flow control (xonxoff),
 * or hardware flow control (rtscts), respectively, of the underlying tty device.
 * serial should be a valid pointer to a Serial handle opened with serial_open() or serial_open_advanced().
 * Returns 0 on success, or a negative Serial error code on failure.
 * @param serial
 * @param baudrate databits parity stopbits xonxoff rtscts
 * @return
 */
int serial_get_baudrate(serial_t *serial, uint32_t *baudrate);
int serial_get_databits(serial_t *serial, unsigned int *databits);
int serial_get_parity(serial_t *serial, serial_parity_t *parity);
int serial_get_stopbits(serial_t *serial, unsigned int *stopbits);
int serial_get_xonxoff(serial_t *serial, bool *xonxoff);
int serial_get_rtscts(serial_t *serial, bool *rtscts);

/**
 * Set the baudrate, data bits, parity, stop bits, software flow control (xonxoff),
 * or hardware flow control (rtscts), respectively, on the underlying tty device.
 * serial should be a valid pointer to a Serial handle opened with serial_open() or serial_open_advanced().
 * Returns 0 on success, or a negative Serial error code on failure.
 * @param serial
 * @param baudrate databits parity stopbits xonxoff rtscts
 * @return
 */
int serial_set_baudrate(serial_t *serial, uint32_t baudrate);
int serial_set_databits(serial_t *serial, unsigned int databits);
int serial_set_parity(serial_t *serial, enum serial_parity parity);
int serial_set_stopbits(serial_t *serial, unsigned int stopbits);
int serial_set_xonxoff(serial_t *serial, bool enabled);
int serial_set_rtscts(serial_t *serial, bool enabled);

/**
 * Return the file descriptor (for the underlying tty device) of the Serial handle.
 * serial should be a valid pointer to a Serial handle opened with serial_open() or serial_open_advanced().
 * This function is a simple accessor to the Serial handle structure and always succeeds.
 * @param serial
 * @return
 */

int serial_fd(serial_t *serial);

/**
 * Return a string representation of the Serial handle.
 * serial should be a valid pointer to a Serial handle opened with serial_open() or serial_open_advanced().
 * This function behaves and returns like snprintf().
 * @param serial
 * @param str
 * @param len
 * @return
 */

int serial_tostring(serial_t *serial, char *str, size_t len);

/**
 * Return the libc errno of the last failure that occurred.
 * serial should be a valid pointer to a Serial handle opened with serial_open() or serial_open_advanced().
 * @param serial
 * @return
 */
int serial_errno(serial_t *serial);

/**
 * Return a human readable error message of the last failure that occurred.
 * serial should be a valid pointer to a Serial handle opened with serial_open() or serial_open_advanced().
 * @param serial
 * @return
 */
const char *serial_errmsg(serial_t *serial);

#endif

