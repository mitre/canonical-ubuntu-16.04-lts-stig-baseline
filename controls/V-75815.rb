control "V-75815" do
  title "The Ubuntu operating system must synchronize internal information
system clocks to the authoritative time source when the time difference is
greater than one second."
  desc  "Inaccurate time stamps make it more difficult to correlate events and
can lead to an inaccurate analysis. Determining the correct time a particular
event occurred on a system is critical when conducting forensic analysis and
investigating system events.

    Synchronizing internal information system clocks provides uniformity of
time stamps for information systems with multiple system clocks and systems
connected over a network. Organizations should consider setting time periods
for different types of systems (e.g., financial, legal, or mission-critical
systems).

    Organizations should also consider endpoints that may not have regular
access to the authoritative time server (e.g., mobile, teleworking, and
tactical endpoints). This requirement is related to the comparison done every
24 hours in SRG-OS-000355 because a comparison must be done in order to
determine the time difference.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000356-GPOS-00144"
  tag "gid": "V-75815"
  tag "rid": "SV-90495r2_rule"
  tag "stig_id": "UBTU-16-030110"
  tag "fix_id": "F-82445r2_fix"
  tag "cci": ["CCI-002046"]
  tag "nist": ["AU-8 (1) (b)", "Rev_4"]
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
  desc "check", "Verify that Network Time Protocol (NTP) is running in
continuous mode.

Check that NTP is running in continuous mode with the following command:

# grep ntpdate /etc/init.d/ntpd

  if ntpdate -u -s -b -p 4 -t 5 $NTPSERVER ; then

If the option \"-q\" is present, this is a finding."
  desc "fix", "The Network Time Protocol (NTP) will run in continuous mode by
default. If the query only option (-q) has been added to the ntpdate command in
/etc/init.d/ntpd it must be removed."

  ntpd_exists = file('/etc/init.d/ntpd').exist?

  if ntpd_exists
    describe command('grep ntpdate /etc/init.d/ntpd').stdout.strip do
      it { should_not match %r(.+(-q).+) }
    end
  else
    describe "The file /etc/init.d/ntpd exists" do
      subject { ntpd_exists }
      it { should be true }
    end
  end
end

