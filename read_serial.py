from time import sleep
import serial

# Set the serial port and parameters
serial_port = '/dev/ttyACM0'  # Change this to your serial device
serial_port1 = '/dev/ttyACM1'  # Change this to your serial device

baud_rate = 57600  # Baud rate of the device (modify as needed)
timeout = 1  # Timeout for reading data (in seconds)

exitFlag = False

while not exitFlag:

    ser = None
    # Open the serial port
    try:
        ser = serial.Serial(serial_port, baudrate=baud_rate, timeout=timeout)
        print(f"Opened serial port {serial_port} at {baud_rate} baud.")
               
    except serial.SerialException as e:
        print(f"Error opening serial port: {e}")

    except KeyboardInterrupt:
        print("Exiting program.")
        exitFlag = True
        break

    if not ser.is_open:
        try:
            ser = serial.Serial(serial_port1, baudrate=baud_rate, timeout=timeout)
            print(f"Opened serial port {serial_port} at {baud_rate} baud.")
            
        
        except serial.SerialException as e:
            print(f"Error opening serial port: {e}")
            sleep(0.1)
            continue

        except KeyboardInterrupt:
            print("Exiting program.")
            exitFlag = True
            break


    # Read data from the serial port
    try:
        while not exitFlag:
            if ser.in_waiting > 0:  # Check if data is available
                data = ser.readline()  # Read a line of data
                # .strip()
                print(f"Received data: {data.decode('iso8859-1').strip()}")
    except KeyboardInterrupt:
        print("Exiting program.")
        exitFlag = True
        continue

    except Exception:
        continue


# Close the serial port when done
if 'ser' in locals() and ser.is_open:
    ser.close()
    print(f"Closed serial port {serial_port}.")
