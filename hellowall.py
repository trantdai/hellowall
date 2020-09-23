#!/usr/bin/env python3

"""HelloWall: Step-by-step firewall automation development guide
"""
import sys
from firelib.firelib.common import freeze, connectors

print('\n *** HELLOWALL: STEP-BY-STEP FIREWALL AUTOMATION DEVELOPMENT GUIDE ***\n')

# CHECK CURRENT FREEZE STATUS
f = freeze.Freeze()
if f.get_freeze():
    sys.exit("There is current full FREEZE in place. Please check with change management. Automation aborted...\n")
else:
    print("There is no current freeze. Automation continued...\n")

print('\n === PAN SECTION ===\n')
# Set target device
pan_target_system = 'testpano1.local.net'

# SSH to Panorama
panconn = connectors.FWSSHConnector(pan_target_system, 'manager', 'PAN')
pansess = panconn.session

# SSH to PAN firewall
'''
panconn = connectors.FWSSHConnector(pan_target_system, 'firewall', 'PAN')
pansess = panconn.session
'''

# Turn off paging
resp = pansess.toggle_paging_setting()

# Run 'show system info' command and get result
cmd = 'show system info'
result = pansess.run_pan_command(cmd)
print(result)
print('Closing SSH session...')
pansess.exit_ssh_session()
