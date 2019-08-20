### This is a ***Work in Progress***. We will release the final version in the ***MASTER*** Branch
### This baseline will continue to change until we do a final release

[![Build Status](https://travis-ci.com/mitre/canonical-ubuntu-16.04-lts-stig-baseline.svg?branch=development)](https://travis-ci.com/mitre/canonical-ubuntu-16.04-lts-stig-baseline)

[Travis CI Build History](https://travis-ci.com/mitre/canonical-ubuntu-16.04-lts-stig-baseline/builds)

# canonical_ubuntu_16.04_lts_stig_baseline

An InSpec profile of the DISA Canonical Ubuntu 16.04 LTS STIG baseline

## Getting Started
The following inputs must be configured in inspec.yml for the profile to run correctly. More information about InSpec inpputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```
  - name: emergency_accounts
    description: Emergency user accounts
    type: Array
    value: []

  - name: temporary_accounts
    description: Temporary user accounts
    type: Array
    value: []

  - name: application_groups
    description: Known Application Groups
    type: Array
    value: []

  - name: known_system_accounts
    description: System accounts that support approved system activities
    type: Array
    value: []

  - name: disallowed_accounts
    description: Accounts that are not allowed on the system
    type: Array
    value: []

  - name: user_accounts
    description: Accounts of known managed users
    type: Array
    value: []

  - name: exempt_home_users
    description: These are `home dir` exempt interactive accounts
    type: Array
    value: []

  - name: security_accounts
    description: Security Personnel accounts
    type: Array
    value: []
```

## TESTING
You can run the inspec profile against the vagrant vm provided. 

### Step 1
Browse into the Vagrant folder and run the command
```
vagrant up
```

### Step 2
Run the following command and make a note of all the values in the output.
```
vagrant ssh-config
```

### Step 3
Run the following command to run the inspec profile. Fill in all the values using information noted earlier.
```
inspec exec $PROFILENAME/ \
        -t ssh://$TARGET_USER@$TARGET_HOST \
        -p $TARGET_PORT \
        -i $TARGET_IDENTITYFILE
        --sudo
```

### Optional
To setup/install inspec on the vagrant vm, run the following commands inside the vm.

```
sudo apt-get -y install ruby ruby-dev gcc g++ make
sudo gem install inspec
```

## NOTICE

© 2018 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

## NOTICE  

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

## NOTICE

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.
