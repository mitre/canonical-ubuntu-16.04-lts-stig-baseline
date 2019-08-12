control "V-75517" do
  title "The file integrity tool must perform verification of the correct
operation of security functions: upon system start-up and/or restart; upon
command by a user with privileged access; and/or every 30 days."
  desc  "Without verification of the security functions, security functions may
not operate correctly and the failure may go unnoticed. Security function is
defined as the hardware, software, and/or firmware of the information system
responsible for enforcing the system security policy and supporting the
isolation of code and data on which the protection is based. Security
functionality includes, but is not limited to, establishing system accounts,
configuring access authorizations (i.e., permissions, privileges), setting
events to be audited, and setting intrusion detection parameters.

    Notifications provided by information systems include, for example,
electronic alerts to system administrators, messages to local computer
consoles, and/or hardware indications, such as lights.

    This requirement applies to Ubuntu operating systems performing security
function verification/testing and/or systems and environments that require this
functionality.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000446-GPOS-00200"
  tag "gid": "V-75517"
  tag "rid": "SV-90197r2_rule"
  tag "stig_id": "UBTU-16-010510"
  tag "fix_id": "F-82145r1_fix"
  tag "cci": ["CCI-002699"]
  tag "nist": ["SI-6 b", "Rev_4"]
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
  desc "check", "Verify that Advanced Intrusion Detection Environment (AIDE)
performs a verification of the operation of security functions every 30 days.

Note: A file integrity tool other than AIDE may be used, but the tool must be
executed at least once per week.

Check that AIDE is being executed every 30 days or less with the following
command:

# ls -al /etc/cron.daily/aide

-rwxr-xr-x 1 root root 26049 Oct 24 2014 /etc/cron.daily/aide

If the \"/etc/cron.daily/aide\" file does not exist or the cron job is not
configured to run at least every 30 days, this is a finding."
  desc "fix", "The cron file for AIDE is fairly complex as it creates the
report. The easiest way to create the file is to update the AIDE package with
the following command:

# sudo apt-get install aide"

  describe file('/etc/cron.daily/aide') do
    it { should exist }
  end
end

