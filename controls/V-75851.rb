control "V-75851" do
  title "The SSH daemon must not allow compression or must only allow
compression after successful authentication."
  desc  "If compression is allowed in an SSH connection prior to
authentication, vulnerabilities in the compression software could result in
compromise of the system from an unauthenticated connection, potentially with
root privileges."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75851"
  tag "rid": "SV-90531r2_rule"
  tag "stig_id": "UBTU-16-030350"
  tag "fix_id": "F-82481r3_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
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
  tag "check": "Verify the SSH daemon performs compression after a user
successfully authenticates.

Check that the SSH daemon performs compression after a user successfully
authenticates with the following command:

# grep Compression /etc/ssh/sshd_config
Compression delayed

If the \"Compression\" keyword is set to \"yes\", is missing, or the returned
line is commented out, this is a finding."
  tag "fix": "Configure SSH to use compression. Uncomment the \"Compression\"
keyword in \"/etc/ssh/sshd_config\" on the system and set the value to
\"delayed\" or \"no\":

Compression no

The SSH daemon must be restarted for the changes to take effect. To restart the
SSH daemon, run the following command:

# sudo systemctl restart sshd.service"
end

