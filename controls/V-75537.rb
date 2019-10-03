# frozen_string_literal: true

control 'V-75537' do
  title "The Apparmor module must be configured to employ a deny-all,
permit-by-exception policy to allow the execution of authorized software
programs and limit the ability of non-privileged users to grant other users
direct access to the contents of their home directories/folders."
  desc  "The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    Utilizing a whitelist provides a configuration management method for
allowing the execution of only authorized software. Using only authorized
software decreases risk by limiting the number of potential vulnerabilities.
Verification of white-listed software occurs prior to execution or at system
startup.

    Users' home directories/folders may contain information of a sensitive
nature. Non-privileged users should coordinate any sharing of information with
an SA through shared resources.


  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000368-GPOS-00154'
  tag "satisfies": %w[SRG-OS-000368-GPOS-00154 SRG-OS-000370-GPOS-00155]
  tag "gid": 'V-75537'
  tag "rid": 'SV-90217r2_rule'
  tag "stig_id": 'UBTU-16-010610'
  tag "fix_id": 'F-82165r1_fix'
  tag "cci": %w[CCI-001764 CCI-001774]
  tag "nist": ['CM-7 (2)', 'CM-7 (5) (b)', 'Rev_4']
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
  desc 'check', "Verify the Ubuntu operating system is configured to employ a
deny-all, permit-by-exception policy to allow the execution of authorized
software programs and access to user home directories.

Check that \"Apparmor\" is configured to employ application whitelisting and
home directory access control with the following command:

# sudo apparmor_status

apparmor module is loaded.
13 profiles are loaded.
13 profiles are in enforce mode.
   /sbin/dhclient
   ...
   lxc-container-default-with-nesting
0 profiles are in complain mode.

If the defined profiles do not match the organization’s list of authorized
software, this is a finding."
  desc 'fix', "Configure the Ubuntu operating system to employ a deny-all,
permit-by-exception policy to allow the execution of authorized software
programs.

Install \"Apparmor\" (if it is not installed) with the following command:

# sudo apt-get install libpam-apparmor

Enable/Activate \"Apparmor\" (if it is not already active) with the following
command:

# sudo systemctl enable apparmor.service

Start \"Apparmor\" with the following command:

# sudo systemctl start apparmor.service

Note: Apparmor must have properly configured profiles for applications and home
directories. All configurations will be based on the actual system setup and
organization and normally are on a per role basis. See the \"Apparmor\"
documentation for more information on configuring profiles."

  describe 'Manual test' do
    skip 'This control must be reviewed manually'
  end
end
