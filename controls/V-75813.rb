control "V-75813" do
  title "The Ubuntu operating system must compare internal information system
clocks at least every 24 hours with a server which is synchronized to an
authoritative time source, such as the United States Naval Observatory (USNO)
time servers, or a time server designated for the appropriate DoD network
(NIPRNet/SIPRNet), and/or the Global Positioning System (GPS)."
  desc  "Inaccurate time stamps make it more difficult to correlate events and
can lead to an inaccurate analysis. Determining the correct time a particular
event occurred on a system is critical when conducting forensic analysis and
investigating system events. Sources outside the configured acceptable
allowance (drift) may be inaccurate.

    Synchronizing internal information system clocks provides uniformity of
time stamps for information systems with multiple system clocks and systems
connected over a network.

    Organizations should consider endpoints that may not have regular access to
the authoritative time server (e.g., mobile, teleworking, and tactical
endpoints).
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000355-GPOS-00143"
  tag "gid": "V-75813"
  tag "rid": "SV-90493r2_rule"
  tag "stig_id": "UBTU-16-030100"
  tag "fix_id": "F-82443r2_fix"
  tag "cci": ["CCI-001891"]
  tag "nist": ["AU-8 (1) (a)", "Rev_4"]
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
  desc "check", "The system clock must be configured to compare the system clock
at least every 24 hours to the authoritative time source.

Note: If the system is not networked this item is Not Applicable.

Check the value of \"maxpoll\" in the \"/etc/ntp.conf\" file with the following
command:

# sudo  grep -i maxpoll /etc/ntp.conf
maxpoll = 17

If \"maxpoll\" is not set to \"17\" or does not exist, this is a finding.

Verify that the \"ntp.conf\" file is configured to an authoritative DoD time
source by running the following command:

# grep -i server /etc/ntp.conf
server 0.us.pool.ntp.org iburst

If the parameter \"server\" is not set, is not set to an authoritative DoD time
source, or is commented out, this is a finding."
  desc "fix", "Note: If the system is not networked this item is Not Applicable.

To configure the system clock to compare the system clock at least every 24
hours to the authoritative time source, edit the \"/etc/ntp.conf\" file. Add or
correct the following lines, by replacing \"[source]\" in the following line
with an authoritative DoD time source.

maxpoll = 17
server [source] iburst

If the \"NTP\" service was running and the value of \"maxpoll\" or \"server\"
was updated then the service must be restarted using the following command:

# sudo systemctl restart ntp.service

If the \"NTP\" service was not running then it must be started."
end

