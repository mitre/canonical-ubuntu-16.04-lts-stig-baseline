# frozen_string_literal: true

control 'V-75857' do
  title "All networked systems must have and implement SSH to protect the
confidentiality and integrity of transmitted and received information, as well
as information during preparation for transmission."
  desc  "Without protection of the transmitted information, confidentiality and
integrity may be compromised because unprotected communications can be
intercepted and either read or altered.

    This requirement applies to both internal and external networks and all
types of information system components from which information can be
transmitted (e.g., servers, mobile devices, notebook computers, printers,
copiers, scanners, and facsimile machines). Communication paths outside the
physical protection of a controlled boundary are exposed to the possibility of
interception and modification.

    Protecting the confidentiality and integrity of organizational information
can be accomplished by physical means (e.g., employing physical distribution
systems) or by logical means (e.g., employing cryptographic techniques). If
physical means of protection are employed, logical means (cryptography) do not
have to be employed, and vice versa.


  "
  impact 0.7
  tag "gtitle": 'SRG-OS-000423-GPOS-00187'
  tag "satisfies": %w[SRG-OS-000423-GPOS-00187 SRG-OS-000424-GPOS-00188
                      SRG-OS-000425-GPOS-00189 SRG-OS-000426-GPOS-00190]
  tag "gid": 'V-75857'
  tag "rid": 'SV-90537r1_rule'
  tag "stig_id": 'UBTU-16-030420'
  tag "fix_id": 'F-82487r1_fix'
  tag "cci": %w[CCI-002418 CCI-002420 CCI-002421 CCI-002422]
  tag "nist": ['SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)', 'Rev_4']
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
  desc 'check', "Verify the \"ssh\" meta-package is installed.

Check that the ssh package is installed with the following command:

$ dpkg -l | grep openssh

ii openssh-client 1:7.2p2-4Ubuntu2.1
amd64 secure shell (SSH) client, for secure access to
remote machines
ii openssh-server 1:7.2p2-4Ubuntu2.1
amd64 secure shell (SSH) server, for secure access
from remote machines
ii openssh-sftp-server 1:7.2p2-4Ubuntu2.1
amd64 secure shell (SSH) sftp server module, for SFTP
access from remote machines

If the \"openssh\" server package is not installed, this is a finding.

Check that the \"sshd.service\" is loaded and active with the following command:

# systemctl status sshd.service | egrep -i \"(active|loaded)\"

Loaded: loaded (/usr/lib/systemd/system/sshd.service; enabled)
Active: active (running) since Sun 2016-06-05 23:46:29 CDT; 1h 4min ago

If \"sshd.service\" is not active or loaded, this is a finding."
  desc 'fix', "Install the \"ssh\" meta-package on the system with the following
command:

# sudo apt install ssh

Enable the \"ssh\" service to start automatically on reboot with the following
command:

# sudo systemctl enable sshd.service"

  describe package('openssh-server') do
    it { should be_installed }
  end

  describe service('sshd') do
    it { should be_enabled }
    it { should be_installed }
    it { should be_running }
  end
end
