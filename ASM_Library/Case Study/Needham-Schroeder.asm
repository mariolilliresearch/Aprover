// a simple example of the Library usage

asm Needham-Schroeder

import StandardLibrary
import CTLlibrary

signature:
	domain Alice subsetof Agent
	domain Bob subsetof Agent
	domain Eve subsetof Agent
	
	
	
	enum domain StateA = { IDLE_A | WAIT_MESS2 |  END_A }
	enum domain StateB = { WAIT_MESS1 |  WAIT_MESS3 | END_B}
	
	enum domain Message = { MESS_NA_IDA |  MESS_NA_NB |  MESS_NB | 
							ENC_MESS_NA_IDA | ENC_MESS_NA_NB |ENC_MESS_NB| ERROR}
							
	enum domain Field={ NA |ID_A |NB }				
							
	enum domain AsymPubKey={ PUBKA | PUBKB | PUBKE}
	enum domain AsymPrivKey={ PRIVKA | PRIVKB | PRIVKE }
	/*------------------------------------------------------------------- */
	//                   Protocol flow description 
	/*------------------------------------------------------------------- */
	
	//controlled protocolMessage: Prod(Agent,Agent)-> Message
	controlled protocolMessage: Prod(Alice,Eve)-> Message
	controlled protocolMessage: Prod(Eve,Alice)-> Message
	controlled protocolMessage: Prod(Bob,Eve)-> Message
	controlled protocolMessage: Prod(Eve,Bob)-> Message
	
	controlled internalStateA: Alice -> StateA
	controlled internalStateB: Bob -> StateB
	
	/*------------------------------------------------------------------- */
	//                  Cryptographic function
	/*------------------------------------------------------------------- */
	
	static asymEnc: Prod(Message,AsymPubKey)-> Message
	static asymDec: Prod(Message,AsymPrivKey)-> Boolean
	
	/*------------------------------------------------------------------- */
	//                   Principals' Knowledge 
	/*------------------------------------------------------------------- */
	
	//controlled knowsField:Prod(Agent,Field)->Boolean
	controlled knowsField:Prod(Alice,Field)->Boolean
	controlled knowsField:Prod(Bob,Field)->Boolean
	controlled knowsField:Prod(Eve,Field)->Boolean
	
	controlled knowsAsymPubKey:Prod(Alice,AsymPubKey)->Boolean
	controlled knowsAsymPubKey:Prod(Bob,AsymPubKey)->Boolean
	controlled knowsAsymPubKey:Prod(Eve,AsymPubKey)->Boolean
	
	controlled knowsAsymPrivKey:Prod(Alice,AsymPrivKey)->Boolean
	controlled knowsAsymPrivKey:Prod(Bob,AsymPrivKey)->Boolean
	controlled knowsAsymPrivKey:Prod(Eve,AsymPrivKey)->Boolean
	
	/*------------------------------------------------------------------- */
	//                      Agent instantiation
	/*------------------------------------------------------------------- */
	static alice:Alice
	static bob:Bob
	static eve:Eve
definitions:

	function asymEnc($m in Message, $pub in AsymPubKey)=
		if($m=MESS_NA_IDA and $pub=PUBKB)then
			ENC_MESS_NA_IDA
		else
			if($m=MESS_NA_NB and $pub=PUBKA)then
				ENC_MESS_NA_NB
			else
				if($m=MESS_NB and $pub=PUBKB)then
					ENC_MESS_NB
				else
					ERROR
				endif
			endif
		endif
		
	function asymDec($m in Message, $priv in AsymPrivKey)=
		if($m=ENC_MESS_NA_IDA and $priv=PRIVKB)then
			true
		else
			if($m=ENC_MESS_NA_NB and$priv=PRIVKA)then
				true
			else
				if($m=ENC_MESS_NB and $priv=PRIVKB)then
					true
				else
					false
				endif
			endif
		endif

	rule r_send_mess1 =		
		let ($e=eve) in
			if(internalStateA(self)=IDLE_A)then
				par
					knowsField(self,NA):=true	
					knowsField(self,ID_A):=true
					protocolMessage(self,$e ):= asymEnc(MESS_NA_IDA,PUBKB )
					internalStateA(self):= WAIT_MESS2
				endpar
			endif
		endlet
		
	rule r_replay_mess1 =		
		let ($a=alice,$b=bob) in
			if(protocolMessage($a,self) = ENC_MESS_NA_IDA and protocolMessage(self,$b) != ENC_MESS_NA_IDA)then
				par
					if(knowsAsymPrivKey(self,PRIVKB)=true)then
						if(asymDec(ENC_MESS_NA_IDA,PRIVKB)=true)then
							par
								knowsField(self,NA):=true	
								knowsField(self,ID_A):=true
							endpar
						endif
					endif
					protocolMessage(self,$b):= ENC_MESS_NA_IDA
				endpar
			endif
		endlet
		
	rule r_send_mess2 =		
		let ($e=eve) in
			if(internalStateB(self)=WAIT_MESS1 and protocolMessage($e,self)= ENC_MESS_NA_IDA)then
				if(knowsAsymPrivKey(self,PRIVKB)=true)then
					par
						if(asymDec(ENC_MESS_NA_IDA,PRIVKB)=true)then
							par
								knowsField(self,NA):= true	
								knowsField(self,ID_A):= true
								protocolMessage(self,$e):= asymEnc(MESS_NA_NB,PUBKA )
								internalStateB(self):= WAIT_MESS3
							endpar
						endif
						knowsField(self,NB):= true
						
					endpar
				endif
			endif
		endlet
	
	rule r_replay_mess2 =		
		let ($a=alice,$b=bob) in
			if(protocolMessage($b,self) = ENC_MESS_NA_NB and protocolMessage(self,$a) != ENC_MESS_NA_NB)then
				par
					if(knowsAsymPrivKey(self,PRIVKA)=true)then
						if(asymDec(ENC_MESS_NA_NB,PRIVKA)=true)then
							par
								knowsField(self,NA):=true	
								knowsField(self,NB):=true
							endpar
						endif
					endif
					protocolMessage(self,$a):= ENC_MESS_NA_NB
				endpar
			endif
		endlet
		
	rule r_send_mess3 =		
		let ($e=eve) in
			if(internalStateA(self)=WAIT_MESS2 and protocolMessage($e,self) = ENC_MESS_NA_NB)then
				if(knowsAsymPrivKey(self,PRIVKA)=true)then
					par
						if(asymDec(ENC_MESS_NA_NB,PRIVKA)=true)then
							knowsField(self,NB):=true
						endif
						protocolMessage(self,$e):= asymEnc(MESS_NB,PUBKB)
						internalStateA(self):=END_A
					endpar
				endif
			endif
		endlet
	
	rule r_replay_mess3 =		
		let ($a=alice,$b=bob) in
			if(protocolMessage($a,self) = ENC_MESS_NB and protocolMessage(self,$b) != ENC_MESS_NB)then
				par
					if(knowsAsymPrivKey(self,PRIVKB)=true)then
						if(asymDec(ENC_MESS_NA_NB,PRIVKA)=true)then
							knowsField(self,NB):=true
						endif
					endif
					protocolMessage(self,$b):= ENC_MESS_NB
				endpar
			endif
		endlet
		
	rule r_check_mess3 =		
		let ($e=eve) in
			if(internalStateB(self)= WAIT_MESS3 and protocolMessage($e,self) = ENC_MESS_NB )then
				if(knowsAsymPrivKey(self,PRIVKB)=true)then
					par
						if(asymDec(ENC_MESS_NB,PRIVKB)=true)then
							knowsField(self,NB):=true
						endif
						internalStateB(self) := END_B
					endpar
				endif
			endif
		endlet

	rule r_agentERule  =		
			par				
				r_replay_mess1[]
				r_replay_mess2[] 
				r_replay_mess3[]
			endpar
	
	rule r_agentARule  =
		par
			r_send_mess1[]
			r_send_mess3[]
		endpar
		
	rule r_agentBRule  =
		par
			r_send_mess2[]
			r_check_mess3[]
		endpar
		
	//CTLSPEC not(ef(knowsField(eve,NB)=true))
	//CTLSPEC not(ef(knowsField(bob,NB)=true))
	CTLSPEC implies(ef(knowsField(alice,NB)=true and knowsField(bob,NB)=true),ag(not(knowsField(eve,NB)=true)))
	
	// MAIN RULE
	main rule r_Main =
			par
				program(alice)
				program(bob)
				program(eve)
			endpar

// INITIAL STATE
default init s0:
	function internalStateA($a in Alice)=IDLE_A
	function internalStateB($b in Bob)=WAIT_MESS1
	function knowsAsymPrivKey($a in Alice,$priv in AsymPrivKey)=if($priv=PRIVKA)then  true else false endif
	function knowsAsymPrivKey($e in Eve,$priv in AsymPrivKey)=if($priv=PRIVKE )then  true else false endif
	function knowsAsymPrivKey($b in Bob,$priv in AsymPrivKey)=if($priv=PRIVKB)then  true else false endif
	function knowsAsymPubKey($a in Alice,$pub in AsymPubKey)=if($pub=PUBKA or $pub=PUBKB)then true else false endif
	function knowsAsymPubKey($e in Eve,$pub in AsymPubKey)=if($pub=PUBKA or $pub=PUBKB)then  true else false endif
	function knowsAsymPubKey($b in Bob,$pub in AsymPubKey)=if($pub=PUBKA or $pub=PUBKB)then  true else false endif
	function knowsField($b in Bob,$f in Field)=false
	function knowsField($e in Eve,$f in Field)=false
	function knowsField($a in Alice,$f in Field)=false
	
	agent Alice:
		r_agentARule[]

	agent Bob:
		r_agentBRule[]
		
	agent Eve:
		r_agentERule[]
