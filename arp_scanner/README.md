## Arp Scanner
This program allows you to find devices on your network or just find MAC address of a device in your network.

## Allowed Methods
- ```GET```

## Status Codes
- 200 ```OK``` - The request was successful.
- 400 ```Bad Request``` - The request could not be understood or was missing required parameters.

## Request
- Method : ```GET```
- Endpoint : ```http://localhost:5000/arp_scan```
- Params : 
-- ```target``` - Ip Address and Subnet Mask of the Target

## Example Request
```
wget http://localhost:5000/arp_scan?target=10.0.2.1/24
```

## Example Response
```
[
    {
        "ip_addr": "10.0.2.1",
        "mac_addr": "aa:bb:cc:dd:ee:ff"
    }
]
```

## How to Run
First of all, meet the requirements
```
pip install -r requirements.txt
```
Runserver
```
sudo python3 arp_scanner.py
```
- Note: Root user privileges required.