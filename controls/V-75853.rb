# frozen_string_literal: true

control 'V-75853' do
  title 'Remote X connections for interactive users must be encrypted.'
  desc  "Open X displays allow an attacker to capture keystrokes and execute
commands remotely."
  impact 0.7
  tag "gtitle": 'SRG-OS-000480-GPOS-00227'
  tag "gid": 'V-75853'
  tag "rid": 'SV-90533r2_rule'
  tag "stig_id": 'UBTU-16-030400'
  tag "fix_id": 'F-82483r2_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc 'check', "Verify remote X connections for interactive users are encrypted.

Check that remote X connections are encrypted with the following command:

# grep -i x11forwarding /etc/ssh/sshd_config
X11Forwarding yes

If the \"X11Forwarding\" keyword is set to \"no\", is missing, or is commented
out, this is a finding."
  desc 'fix', "Configure SSH to encrypt connections for interactive users.

Edit the \"/etc/ssh/sshd_config\" file to uncomment or add the line for the
\"X11Forwarding\" keyword and set its value to \"yes\":

X11Forwarding yes

The SSH daemon must be restarted for the changes to take effect. To restart the
SSH daemon, run the following command:

# sudo systemctl restart sshd.service"

  describe sshd_config do
    its('x11forwarding') { should cmp 'yes' }
  end
end
