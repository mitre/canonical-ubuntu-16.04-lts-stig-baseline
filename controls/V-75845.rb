control "V-75845" do
  title "The SSH private host key files must have mode 0600 or less permissive."
  desc  "If an unauthorized user obtains the private SSH host key file, the
host could be impersonated."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75845"
  tag "rid": "SV-90525r2_rule"
  tag "stig_id": "UBTU-16-030320"
  tag "fix_id": "F-82475r2_fix"
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
  tag "check": "Verify the SSH private host key files have mode \"0600\" or
less permissive.

Check the mode of the private host key files under \"/etc/ssh\" file with the
following command:

# ls -alL /etc/ssh/ssh_host*key

-rw-------  1 root  wheel  668 Nov 28 06:43 ssh_host_dsa_key
-rw-------  1 root  wheel  582 Nov 28 06:43 ssh_host_key
-rw-------  1 root  wheel  887 Nov 28 06:43 ssh_host_rsa_key

If any private host key file has a mode more permissive than \"0600\", this is
a finding."
  tag "fix": "Configure the mode of SSH private host key files under
\"/etc/ssh\" to \"0600\" with the following command:

#sudo chmod 0600 /etc/ssh/ssh_host*key

The SSH daemon must be restarted for the changes to take effect. To restart the
SSH daemon, run the following command:

# sudo systemctl restart sshd.service"
end

