# Latency Tips and other Good Quotes

**Credits will be listed before any comment, Made byFelipe**

## credits vdam

- don't buy AMD
- disable all meme power saving features in your bios/osyou can find
- all core overclock with fixed voltage
- products who can't optimize for latency make upmarketing terms/features in other direction(into
bandwidth/power saving/RBG/extra features) - 99% ofreviews are fake
- higher FPS on benchmarks means nothing, 0.1%/1%lows matter far more, input latency is almost never
measured
- most benchmarks are for single player PC games whichare just unoptimized console ports - never
cheap out on anything, if you need it, you will useit 5hours+ daily for atleast a year, spend thoseextra
$$$ on a one time purchase to get a good quality product(mobo,pads,ram,cpu,monitor, it applies to
everything)
- RGB is a zoomer meme, turn it off(off means off,not static color, it also sucks), it adds latencyon
keyboard/mice and uses extra power
- Benchmarking is the correct way to measure anything
- Benchmarking is hard, make sure your tests are consistentin the same environment, verify your
benchmarking method is the correct way to measurewhat you want to prove
- frequencies/latency reductions scaling is not linear,its chrono-exponential (45ns RAM latency vs 39ns
RAM latency feeling is night and day)
- dedicate 2 weeks of your life to overclock yourRAM properly,do it for all RAM timings, most people
cba to do it, but it's worth it far more than youcan imagine (OC ram benchmark vids on yt dont showu
latency/smoothness of proper ram OC related to input)
- tightening RAM timings is very hard, some timingsmay be lower but perform worse, some might be
higher but also worse, test across different loads(ultra high menu fps, ingame, high cpu load, highgpu
load,memtests)
- your tight RAM timings might have error correction,higher timings perform better and have no
stutters due to no error correction
- finding the proper RAM timings takes time, but worthit in the end, test each one individually and then
tune them together
- close all programs while in a competitive game
- never buy a gaming chair, they are all scam, buya proper office chair from herman miller (used
embody/aeron)
- everything with a "Gaming" label is a marketingscam (feature/product/software)
- disable CPU idle states, if you can't do it 24/7,disable them before you enter a game and enable
afterwards
- on windows 10 explorer.exe has huge amount of threads,kill it before gaming
- if your game has a launcher/client, try to killthe process while ingame and see if everything works,do it
every time
- get proper VESA certified cables for monitor
- disable all extra features on your monitor (dark/contrastboost/crosshair/overlays/upscaling/aspect
ratio adjustments)
- overclock everything you can, cpu,mobo,ram,monitor,mouse,the hardware you purchase out of the box
is tuned for most common use case targeted at a groupconsisting of a 10 yo child, your grandma and a
high end overclocker using it
- don't buy Logitech peripherals(specially GProWirelesspower-saving mice), they all suck, GHub sucks
even more


- don't use real time priority for game process, its for critical system threads
- overclock your GPU memory but be aware it has errorcorrection so you can clock higher, doesnt mean
u get more FPS ( use ultra high fps [XXXX FPS] measurementtool - liblava triangle example is a good one)
- setting I/O priority and proc priority of svchostservices can lower latency/improve mouse pooling,but
don't set network/audio services to low or you willhave stutters (split them using registry configuration
into proper groups)
- setting the MSI queue limit of devices to max theysupport is almost always better, especially for USB
and Network
- when tuning RAM timings aim for higher fps backedby better consistency in ultra high FPS menu, this
translates into better responsiveness/smoothness,even if you lose a bit ns of latency
https://github.com/integralfx/MemTestHelper/blob/master/DDR4%20OC%20Guide.md
- Don't chase aida lowest latency number, tuning ramis much more complex than that, you need to aim
to find the best out of lowest latency possible withouterror correction AS WELL as without any
clock/timing correction. Clock/timing correction ofRAM happens when you drop some timing far below
than its supposed to be, tFAW (Four activate window)or tRAS in most of the cases,just because it boots,
works and gives you some lower latency in aida, doesntmean its actually better in game, if you are on
win10 use liblava fps example demo or something withreally high FPS (Warfork on steam w7/w10) to
see how reducing tRAS/tFAW affects your FPS, lookat 0.1% 1% lows, and frame consistency, a lot of
people dumped their tRAS/tFAW just to chase 0.3nsram latency reduction, but having proper timings
derived out of formulas (tCL+tRCD + tRP) = tRAS (+/-1)and for tFAW( the 5 other timings added
together - TFAW=TRRD+TWTR+TCWL+TRTP) will give youfar better consistency/smoother feeling
Good beginner method of making sure your ram is stableand measuring the performance 1. boots? make
sure no programs are running ( discord/browser etc)2. aida benchmark 3. repeat aida benchmark 4.
check read write copy speeds as well as latency (didanything drop a lot? - error/timing correction, espif
you lowered timing and ram latency went up) 5. run
memtest64(https://www.techpowerup.com/memtest64/),enable "stop on error", let it run for 10mins 6.
look at your FPS in ultra high fps menu/bench, lookat consistency, highest fps, how often its hittingit,
how often are you hitting lowest fps, how much instabilityis at the lowest fps, how long do you stay at
high fps, whats the FPS distribution 7. run SuperPIto verify everything works 8. stop asking me if you
should buy Kharu
https://www.aliexpress.com/item/32750671016.html?mp=1ram cooler that u should deff buy ( $15 or
so ), helps with OC for low latency ram, as well assmoothness since its active cooling and keeps theram
chips cooler. 4500RPM max , ~ 3500RPM is barely audible,might want to consider removing scam
heatspreaders on your ram aswell if u do get it pleasenote that this is basically the most
cheap/scuffed/easiest solution to see impact of coolingyour RAM, there are far far far superior/better
methods out there and I only used this as alpha teststarting point you should also use hair dryer toheat
up your ram heatsinks - 20-30cm distance aimed at1/4 or 1/3 per part (bottom/middle/upper) of
heatsink for 5-10seconds then take heatsinks off easilyby peeling them (another 10-20% improvement
with ram fan over with just ram fan and having heatsinkson - they are scam )
- temps are everything, CPU/mobo/ram/PCB traces, theyall rip beyond 60deg C - thermal grizzly
conductonaut is best thermal paste, rest suck - watch2-5 videos about how to apply liquid metal - check
if your cooler bottom plate is aluminum or not (liquidmetal + aluminum = rip ) - get Rockit copper IHSfor
your Intel CPU and enjoy ~ 8-20deg C temp drop withdelid and 2x conductonaut
- delid with derbau8er delid kid
- place liquid metal (conductonaut) on the die aswell as on IHS on top for cooler
- make sure to research how liquid metal works andits re-application
- furman high end power conditioners are amazing(forEU), entry (sub $500) are for lamps and audio
equipment, not for 5GHz CPUs
- software for monitoring temps sucks because CPUsmicrospike and microthrottle in nanoseconds and
software updates every 500ms


- Intel has shadow/stealth temperature throttling
- bootable ISO Linpack Xtreem stable or gtfo (loweryour OC/voltages first run or 110c insta) - 65
degrees C is max your CPU should ever hit, 40 degC is goal for non liquid cooling
- RAM latency and RAM temperature are the biggestbottlenecks in modern computer systems (by far,
like 1:30000000000 over anything else)
- FPS is useless scam NPCs jerk off to, those framesneed to be delivered to monitor and shown on
screen through the entire pipeline - high qualityPSU is a must for good OCing, don't fall for gold/bronze
sub 850W rated memes - its about ripple measures ofPSU, Corsair 1600i is godmode]
- more voltage is always better if you can keep itcool - get a 360mm AIO cooler for your CPU (EVGA
CLC360/Arctic liquid freezer 2) - ram heatsinks suck,remove them with hair dryer and get a ram fan
either purchase a finished solution or point a ziptiedfan to them - get Noctua/Arctic fans for your case
(very possible EMI problems/ stay away from PWM)
- figure out proper airflow for your case - make sureu have a good airflow case without dust/mesh filter
scams
- 1 degree C lower ram temperature is worth ~ 15-30%in performance (latency/smoothness/fps),
depending on how good your ram OC/cpu OC is - tRC/tRCD/tRAS/tRPare worth far more than tCL for
RAM OC
- CR1 on RAM or your RAM is useless
- tREFI should be as high as possible, its very important
- tRFC should be as low as possible, very importantfor smoothness and responsiveness (even just
-1/-2T)
- CPU core clock is worth 10% of CPU uncore clockwhen comparing 100MHz increase for each
- CPU uncore clock should be equal or higher thanCPU core
- CPU uncore clock increase of 100MHz will give you~1-3ns gains in latency
- AIDA is a dogshit scam tool for CES reviewers, useIMLC(Intel Memory Latency Checker) and read the
manual, its worth it
- IMLC loaded latency is what matters (up to ~ 10GB/sbandwidth used) as well as L2 hit/L2 miss
latency(uncore dependant)
- AIDA latency numbers are useless metric for anythingin real life and due to broken benchmark it
doesnt even reflect changes for all timings
- EVGA dark for z390/z490 is godmode board above everythingelse
- use multiple RAM testing tools for few hours oneach
- you can fail due to temperature floor rising slowlyif you keep test running for long periods - its bestto
test with as many mem testing tools as u can find
- every memory has different physical properties ofchips/cells and they all fail/react differently onsame
access/test patterns
- memory cells retention time(how well data is stored)can change randomly every day/hour, so test
multiple days to ensure you are 100% stable
- even if you don't adjust your timings, lower RAMtemperature will give you improvement - it is highly
recommended and important to disable ram power downin bios (if you can't find it, use grub/modded
bios) - your ram latency OC/adjustment is close touseless if you are on AMD, sell it and buy Intel- your
ram latency OC is useless if you are not on CR1 -your ram latency OC is useless if you can't disable
power down mode because it's like turning off yourmonitor on and off every second to save power, also
it adds ~5-8ns latency - same goes for Self-Refreshin bios - when testing RAM stability its about hitting
it with as many different read/write patterns possible
- RAM cells can and do affect nearby rows/cells -more aggressive test = better stability test = failsfaster
- long tests which do the same test pattern over andover are useless and just test temperatures - RAM
latency reduction scaling is >>NOT<< linear. 50ns-> 35ns is same performance increase (~40% PER
CORE) as 35ns -> 30ns, also as 30ns -> ~27ns) - "safe"voltages people on overclocking forums tell you


are wrong, same goes for manufacturers and what they say, they give you lowest safe voltage on highest
temps on most scuffed mobo on lowest abortion survivingbin components

- if you are rich then let go of mortal constraintsand unleash the voltages/clocks/timings until it
breaks/burns (you will learn a lot more how it actuallyworks/reacts with whole system than shaking and
reading OCN 12k posts experts)
Example of ram temperature with and without heatspreaders:
ram with heatspreader + fan: 44-42 degrees
ram with heatspreader: 46-44 degrees
ram without spreader + fan: 37-37 degrees
ram without spreader 42-42 degrees
- if your router/modem is near your PC, move it asfar away as u can (check your ethernet cable forsignal
over longer distances, but other side of room is okig)
- increasing PCH voltage[do it in small steps] (responsiblefor PCH/gpu microstutters(verified)
improvement/usb) may help gain responsiveness, doit in small increments on SHUTDOWN in BIOS,
meaning apply value -> shut down -> shut down again-> go into windows
- don't have a phone on desk near PC, its beamingstuff in it and your mouse
- check your power cables(PSU/monitors/router/amp/dacetc..) and see if they are hot(electrical
resistance of copper increases with temperatures,all of them suck if u run 5GHz C states off low latency
PC
- DON'T use phone charger adapters to power anythingin PC
- if you use stock/shitty cheap power cables lookinto getting some high quality isolated ones - before
you even start doing ANYTHING with RAM OCing, especiallyfor low latency, REMOVE THE
HEATSINKS ON THEM (watch 2-3 videos on youtube howto do it - seriously it's not that hard)
- before you start doing any RAM OC, get a fan toblow over them, either with zipties or other methods,
best RAM OCs are gained from lower temperatures -1 degree C temperature lower means much more
than you think because: 1. it applies through time,2. it applies as a single measure of temperature
currently and 3. it applies at 0.1% lows (or 99% edgecase load) not just in one state of PC load(idle)
- REMOVE mesh/dust filters from your case

## credits kgct

- tweaks suck objectively but since most people havesucky setups (like his) then his tweaks are useful
it's like medicine has to be targeted not genericgeneric never worked some are happy with
compensating since the system feels better vs priorto those modifications they are not concerned over
"what could be" since they got more than 60% of thepotential performance boost

## credits n1kobg

- the majority of the tweaks mostly improve latency& input lag, not max FPS. You can have a boost in
Min. FPS & 1% & 0.1% loads, depending on your hardwarebut do not expect your computer suddenly
starts hitting 600+fps on Ultra. This is not realistic.That's why it's called optimization, not a miracle
(Watch your min. FPS, 1%, 0,1% & Frametimes, not maxFPS. Sometimes you can have fewer FPS less but
better latency). If you want a faster PC, buy a newone.

## credits NRK

- Competitive gamers subconsciously adjust for thelimits of hardware without even realizing it. They
simply test which aiming strategies result in hits,and which do not - and in a Darwinian way, the
strategies which favorably work around hardware limitationsare the ones that win and get passed on. I
realized after moving from a 1khz mouse to a 8khzmouse that I had been subtly trained by 1khz mice


not to attempt flicks past a certain distance. I always choke it up to "well, I guess the aiming odds just
aren't good past that range," except when I swappedto 8khz the range got much further out. I realized
then that my brain had adapted for all those yearsto a particular hardware limitation. Competitive
gaming is filled with this. The specific speed atwhich they pan their camera around to maintain visual
acuity, the specific way they strafe their characters,and yes, in particular, the way they aim & shoot- all
of this is influenced heavily by the properties ofgamers' hardware in ways that are not immediately
obvious.

## credits Zoyata

- "Placebo is anything that is not DISTINCTIVELY betteror worse than the other available options."
"Placebo is anything that is a temporary 'fix' andmust be repeated over and over to achieve similar
results." "Placebo is anything that you do not understandenough to make an educated decision outside
of "feel"." "Placebo is anything that can not be measuredvia controlled testing." "Placebo is anything that
when weighing available options, you're unable totell the difference due to uncontrollable factors
impacting results.”

## credits Unknown

- “On the contrary, less is more. You don’t want morechanges, you want to take out what was bloated in
Windows, minimize your impact on the integrity ofyour OS, avoid too many changes that are borderline
placebo, and then go back to playing the game andpracticing. The longer you spend trying to make the
game feel perfect, the worse it will feel, and theless you will play. Do a few simple changes, makeit feel
good, and then enjoy your game of choice. If you findthe optimization process fun and want to learn
more about it than you want to learn playing the gameitself, then that is also fine. It is your choiceand
your time. However, do not be so focused on makingthe game run well that you forget to play the game.
This was my mistake and many others made this errorand continue to. By the time we had our game
running perfectly, we hated the game and all its problems.This is an argument for paying for services to
help you do this, as it saves you the time and anxietyof learning to alter your OS and learning
optimization in general."

## credits Timecard

- Does interrupt moderation rate have an effect ondeferred procedure call (DPC) or interrupt service
routine (ISR) latency, and what are the key differencesbetween each of the settings? Yes, during the
simulations it was found that it had more of an impacton DPC latency processing times over ISR,
however each setting didn't scale equally as higherinterrupt moderation values were used however this
may be dependant other factors such as RSS, RSS affinity,rx/tx buffers, and timer resolution and the
traffic simulation itself.
- Interrupt Moderation Disabled produced the samenumbers as with Enabled but Off
- NDIS dpc latency spread (across cores) isn't alwaysequally balanced between runs but DPC latency
performance does not change regardless
- DPC latency in general is consistent between runs
- The gap between Off and the next least restrictivesetting (minimal) is very significant
- The proper ordering of these settings from leastto most interrupt requests are:
    ○ Extreme > High > Medium > Adaptive (Also dependenton load) > Low > Minimal >
       Off/Disabled
- Overall Medium seemed to have the least impact onuser experience/gaming while still providing low
DPC latency. A very low DPC latency can still be achievedwith a medium interrupt moderation value in
which DPCs are processed 90% equal to or below 1 usecsfor high volume small packet UDP
communications (gaming).


- Disabling NetworkThrottlingIndex feature improvesoverall network performance and latency? Not
completely true, NDIS.sys DPC latency is increasedquite notably when disabled.
- A very common recommendation in many performanceenhancement/gaming guides state that
disabling NetworkThrottleIndex improves network performanceand latency because in theory it should
prevent rate limiting and quality of service (QoS)interactions.
- The main purpose of NetworkThrottlingIndex is toreduce (rate limit) calls which would otherwise
impact real time audio and perhaps cause stutter orother audible artifacts.
- Disabling it may increase throughput should thethroughput exceed the default receiving packets per
millisecond (ppms) limit (NetworkThrottleIndex: 10decimal, 10 packets per millisecond, 10,
received packets per second which is roughly ~ 15Mbpswith 1500byte Ethernet MTU) but it does not
improve DPC latency which is probably more beneficialfor lower latency applications such as video
games.
- It's unclear why DPC processing latency is muchlower when this feature is enabled even when you're
not reaching the inbound receive rate limit in comparisonto disabling the feature completely which
removes any throttling.
- To learn mouse about Network Throttling Index seetheTechnical Referencesarticle Multimedia Class
Scheduler Service (MMCSS) Vista Multimedia Playbackand Network Throughput written by Mark
Russinovich.
- You can test this for yourself using xperf, starta capture for dpcisr and compare the results of bothfor
NDIS.sys.

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows
NT\CurrentVersion\Multimedia\SystemProfile\NetworkThrottlingIndex
Off: DWORD Value 0xFFFFFFFF (Hex)
On: DWORD Value 10 (Decimal), Default - Range:Decimal 1-

You should see a similar result as below during loadsuch as gameplay. Note: Intel tends to be closerto
<= 1-2 usecs (microseconds) where as Realtek is muchhigher, around with some around <= 32 usecs and
most <= 4 usecs when most network optimizations areapplied.
Intel
○ Disabled, 0xFFFFFFFF

```
○ Enabled, Decimal 10
```

## credits LAG Discord

Calypto

- I personally haven't found any in game benefit tolowering tWR and tRTP
the more I raised them the smoother my game was. tRTPreally rapes latency but it was worth it for me
- Don’t force timer resolutions if you disabled HPETin BIOS as it results inhigher memory latency

sieger

- The idea is tRTP: read to precharge delay, so thelowest is good. TWR : write recovery time, so it'slike
the cycles required after a valid write and prechargeoperation. It's kind of a validation of your data
written properly. So 2x is kind of validating afterevery 2x read and charge. For me when tWR is a little
loose; in here 2 times tRTP they are in sync. So itwill be more consistent in theory. Might not be the
fastest but in sync. When I'm setting tWR i alwayscheck the lowest first, and try a little loose, then2x. 2x
mostly gave me the best result. When using more than32gb loose tWR gave better result with 16 mostly
2x and 1x gave better result Also with some dimmsi got better with tRTP=tWR but as i said when they
sync it's better
You really need to check as not every stick will givethe same results. Just my findings
If my logic is flawed please let me know. But findingsconfirm imho
- I totally agree with calypto, looser timings withtRTP and tWR give a really smooth experience. I am
generally using 10-10, 12-

## credits Melody


the concept of prioritization itself is a misconcept
because if you prioritize the game, it's not prioritized
it prioritizes CPU execution and everything else canstall
ie.
the game relies on drivers and background windowscomponents
-> the game stalls background stuff itself
that's the main reason why games stutter like hellwhen using "real time" priority
and why it input lags like hell
you end up prioritizing stuff like video driver, specificservices, and at the end of the day you end up
putting everything on same priority and end-up ona paradox
so you're actually better off using a homogeneouspriority scheduling and making sure everything has
the same CPU/GPU times
so the concept of "priority boost" itself is a misconceptas well, as well as "game mode" and stuff like that
then people shall keep making graphs and claimingthings when they're running on such paradox


