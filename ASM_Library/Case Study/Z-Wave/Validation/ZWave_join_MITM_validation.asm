asm ZWave_join_MITM_validation

import StandardLibrary
import CTLlibrary

signature:
	domain Initiator subsetof Agent
	domain Receiver subsetof Agent
	domain Intruder subsetof Agent
	
	
	/*------------------------------------------------------------------- */
	//               Custom domain for Z-Wave Protocol
	/*------------------------------------------------------------------- */
	//Timeout		
	enum domain Time = { TB1 | TA1 | TB2 | TAI1 | TA2 | TB3 | TAI2 | TBI1} 
	
	// Device(Receiver Node) NAT:S2 native security, UP:S2 update device(No QR code o Key printed) 
	enum domain SlaveType = { DOOR_LOCK_NAT | DOOR_LOCK_UP | GARAGE_LOCK_NAT | GARAGE_LOCK_UP | SWITCH_NAT 
							| LIGHT_NAT | SENSOR_NAT | SECURITY_SENSOR_NAT | THERMOSTAT_NAT | THERMOSTAT_UP 
							| ALARM_NAT | ALARM_UP | LEGACY_DEVICE} 
							 
	//Initiator that supports S2 security
	enum domain ControllerType = {CONTROLLER_S2}
	/*------------------------------------------------------------------- */
	//                    CryptoLibrary domain
	/*------------------------------------------------------------------- */
	enum domain StateInit = { INIT_CTRL | WAIT_EVAL_CSA | WAIT_EVAL_KEX_CURVE | WAIT_EVAL_KEX_SCHEME 
						 | WAIT_EVAL_KEX_KEY | WAIT_EVAL_USER_KEY | WAIT_SEI_KEX_SET_ECHO | WAIT_NONCE 
						 | INSERT_PIN | WAIT_PIN_OR_KEY | WAIT_ECDH_PUB_JOIN | WAIT_KEX_REP | ADD_MODE 
						 | WAIT_CTRL_AES| OK_C | ERROR_C | TIMEOUT_C} 
	
	enum domain StateRec = { INIT_SLV | LEARN_MODE | WAIT_KEX_SET | WAIT_EVAL_SET_KEX_KEY | WAIT_EVAL_SET_KEX_SCHEME 
						 | WAIT_EVAL_SET_KEX_CURVE | WAIT_EVAL_SET_CSA | WAIT_ECDH_PUB_CTRL | INSERT_PIN_CSA 
						 | WAIT_NONCE_REP_REI | WAIT_KEX_REPORT_ECHO | OK_S | ERROR_S | TIMEOUT_S}
	
	enum domain Message = { KEX_GET | KEX_REP | KEX_SET | PUB_KEY_REP_JOIN | PUB_KEY_REP_CTRL 
						  | NONCE_GET | NONCE_REPORT | EC_SEI_KEX_SET_ECHO | EC_KEX_REPORT_ECHO 
						  | KEX_FAIL_KEX_KEY | KEX_FAIL_KEX_SCHEME | KEX_FAIL_KEX_CURVE | KEX_FAIL_CANCEL 
						  | KEX_FAIL_AUTH | KEX_FAIL_DECRYPT | EMPTY}
						   
						  
						  
	
						   
						  enum domain Knowledge ={ CSA_0| CSA_1 | SKEX_0 | SKEX_1 |ECDH_0| ECDH_1 | ACCESS_S2_0 
							  | ACCESS_S2_1 |AUTH_S2_0 |AUTH_S2_1| UNAUTH_S2_0 | UNAUTH_S2_1 |  SO_0 | SO_1
						   //Asymmetric Public Key
						   | KPUB_SLV | KPUB_CTRL | KPUB_MITM_CTRL | KPUB_MITM_SLV | OB_KEY_MITM_CTRL 
						   | OB_KEY_MITM_SLV | OB_KEY_SLV | OB_KEY_CTRL | KPUB_ERR 
						   //Asymmetric Private Key
						   | KPRIV_CTRL | KPRIV_SLV | KPRIV_MITM_CTRL | KPRIV_MITM_SLV
						   //Symmetric Public Key
						   | KT1 | KT2 | KT3 | KT_ERROR
						   //Pin used to complete obfuscated keys
						   | PIN_OK | PIN_ERROR					  
						  						   
						   }
						   
	
	//Attacker Mode
	enum domain Modality = {ACTIVE | PASSIVE} 					
		
	
	domain KnowledgeBitString subsetof Any
	domain KnowledgeSymKey subsetof Any
	domain KnowledgeAsymPrivKey subsetof Any
	domain KnowledgeAsymPubKey subsetof Any
	
	domain FieldPosition subsetof Integer
	domain Level subsetof Integer
	domain EncField1 subsetof Integer
	domain EncField2 subsetof Integer

	//ASYMMETRIC KEYS
	//static symKeyToKnowledge:SymKey->Knowledge
	//static isAsymPubKey:Knowledge->Boolean
	
	//enum domain AsimPubKey={ KPUB_Receiver | KPUB_Initiator | KPUB_MITM_CTRL | KPUB_MITM_SLV | OB_KEY_MITM_CTRL 
						   //| OB_KEY_MITM_SLV | OB_KEY_Receiver | OB_KEY_CTRL}
	
	//static isAsymPrivKey:Knowledge->Boolean
	
	//enum domain AsimPrivKey={ KPRIV_Receiver | KPRIV_Initiator | KPRIV_MITM_CTRL | KPRIV_MITM_SLV }
	
	//SYMMETRIC KEYS
	//static isSymKey:Knowledge->Boolean
	//enum domain SymKey={ KT1 | KT2 | KT_ERROR } 
	
	controlled controllerState: Initiator -> StateInit
	controlled slaveState: Receiver -> StateRec
	
	controlled protocolMessage: Prod(Agent,Agent)-> Message
	
	monitored chosenMode: Modality
	controlled mode: Modality
	
	controlled messageField: Prod(Agent,Agent,FieldPosition,Message)->Knowledge
	
	controlled symEnc: Prod(Message,Level,EncField1,EncField2)-> KnowledgeSymKey
	static symDec: Prod(Message,Level,EncField1,EncField2,Agent)-> Boolean
	
	
	static diffieHellman:Prod(KnowledgeAsymPubKey,KnowledgeAsymPrivKey)->KnowledgeSymKey
	/*------------------------------------------------------------------- */
	//            Knowledge  management of the principals 
	/*------------------------------------------------------------------- */
	controlled knowsBitString:Prod(Agent,KnowledgeBitString)->Boolean
	
	controlled knowsSymKey:Prod(Agent,KnowledgeSymKey)->Boolean
	
	controlled knowsAsymPubKey:Prod(Agent,KnowledgeAsymPubKey)->Boolean
	
	controlled knowsAsymPrivKey:Prod(Agent,KnowledgeAsymPrivKey)->Boolean
	
	
	
	//static readKnowledge:Prod(Initiator,Knowledge)->Knowledge
	//static readKnowledge:Prod(Receiver,Knowledge)->Knowledge
	//static readKnowledge:Prod(Intruder,Knowledge)->Knowledge
	/*------------------------------------------------------------------- */
	//               Z-wave protocol specific function
	/*------------------------------------------------------------------- */
	
	
	monitored userGrantS2Access: Boolean	
	monitored userGrantS2Auth: Boolean
	monitored userGrantS2Unauth: Boolean
	monitored userGrantS0: Boolean	
	monitored userCsa: Initiator -> Boolean
	monitored userCsa: Receiver -> Boolean
	monitored pinCode: Boolean	
	monitored controller: Initiator -> ControllerType
	monitored slave: Receiver -> SlaveType
	monitored passed: Time -> Boolean
	monitored nearToEnd: Time -> Boolean //It ends 2 seconds before timer timeout
	monitored slvAbort: Boolean
	monitored ctrlAbort: Boolean
	monitored chosenQrCodeUsage:Boolean
	monitored chosenQrCode:KnowledgeAsymPubKey
	
	controlled qrCodeUseDecison: Boolean
	controlled qrKey:KnowledgeAsymPubKey
	controlled startTimer: Time -> Boolean
	controlled cracked:Boolean
	controlled messageArrived: Boolean
	controlled abortSlvSaved: Boolean
	controlled abortCtrlSaved: Boolean
	
	static recomposePubKey:Prod(Boolean,KnowledgeAsymPubKey)->KnowledgeAsymPubKey
	
	static supportedCsa: SlaveType -> Boolean
	static supportedS2Access: SlaveType -> Boolean
	static supportedS2Auth: SlaveType -> Boolean
	static supportedS2Unauth: SlaveType -> Boolean
	static supportedSkex: SlaveType -> Boolean
	static supportedEcdh: SlaveType -> Boolean
	
	static unSupportedCsa: SlaveType -> Boolean
	static unSupportedS2Access: SlaveType -> Boolean
	static unSupportedS2Auth: SlaveType -> Boolean
	static unSupportedS2Unauth: SlaveType -> Boolean
	static unSupportedSkex: SlaveType -> Boolean
	static unSupportedEcdh: SlaveType -> Boolean
		
	static nodeA: Initiator
	static nodeB: Receiver
	static nodeE: Intruder
	

definitions:
	domain Level = {1}
	domain FieldPosition = {1:7}
	domain EncField1={1}
	domain EncField2={7}
	domain KnowledgeBitString = {CSA_0, CSA_1 ,SKEX_0 , SKEX_1 ,ECDH_0, ECDH_1 ,ACCESS_S2_0 ,
		ACCESS_S2_1 ,AUTH_S2_0 ,AUTH_S2_1, UNAUTH_S2_0 , UNAUTH_S2_1 ,  SO_0 , SO_1, PIN_OK , PIN_ERROR}
	domain KnowledgeSymKey = {KT1 , KT2 , KT3 , KT_ERROR}
	domain KnowledgeAsymPrivKey = {KPRIV_CTRL , KPRIV_SLV , KPRIV_MITM_CTRL , KPRIV_MITM_SLV }
	domain KnowledgeAsymPubKey = {KPUB_SLV , KPUB_CTRL , KPUB_MITM_CTRL , KPUB_MITM_SLV , KPUB_ERR , OB_KEY_MITM_CTRL , OB_KEY_MITM_SLV , OB_KEY_SLV , OB_KEY_CTRL}
	
	function symDec($m in Message,$l in Level,$f1 in EncField1,$f2 in EncField2,$d in Agent)=
		if(knowsSymKey($d,symEnc($m,$l,$f1,$f2))=true)then
			true
		else
			false
		endif
		
		
	function diffieHellman($pub in KnowledgeAsymPubKey,$priv in KnowledgeAsymPrivKey)=
		if(($pub = KPUB_MITM_SLV and $priv = KPRIV_CTRL) or ($pub = KPUB_CTRL and $priv = KPRIV_MITM_SLV))then
				KT1
			else
				if( ($pub = KPUB_SLV and $priv = KPRIV_MITM_CTRL) or ($pub = KPUB_MITM_CTRL and $priv = KPRIV_SLV))then
					KT2
				else
					if( ($pub = KPUB_SLV and $priv = KPRIV_CTRL) or ($pub = KPUB_CTRL and $priv = KPRIV_SLV))then
						KT3
					else
						KT_ERROR
					endif
				endif				
			endif
	
			
	function supportedCsa($s in SlaveType) =
		if( $s=DOOR_LOCK_UP or $s=GARAGE_LOCK_UP or $s=THERMOSTAT_UP or $s=ALARM_UP or $s=LEGACY_DEVICE)then
			//CSA_1
			true
		else
			//CSA_0
			false
		endif
	
	function unSupportedCsa($s in SlaveType) =
		if( $s=DOOR_LOCK_UP or $s=GARAGE_LOCK_UP or $s=THERMOSTAT_UP or $s=ALARM_UP or $s=LEGACY_DEVICE)then
			//CSA_0
			false
		else
			//CSA_1
			true
		endif
	
	function supportedS2Access($s in SlaveType) =
		if( $s=DOOR_LOCK_NAT or $s=DOOR_LOCK_UP  or $s=GARAGE_LOCK_NAT  or $s=GARAGE_LOCK_UP)then
			//ACCESS_S2_1
			true
		else
			//ACCESS_S2_0
			false
		endif
	
	function unSupportedS2Access($s in SlaveType) =
		if( $s=DOOR_LOCK_NAT or $s=DOOR_LOCK_UP  or $s=GARAGE_LOCK_NAT  or $s=GARAGE_LOCK_UP)then
			//ACCESS_S2_0
			false
		else
			//ACCESS_S2_1
			true
		endif
		
	function supportedS2Auth($s in SlaveType) =
		if( $s=SECURITY_SENSOR_NAT or $s=THERMOSTAT_NAT  or $s=THERMOSTAT_UP or $s=ALARM_NAT  or $s=ALARM_UP )then
			//AUTH_S2_1
			true
		else
			//AUTH_S2_0
			false
		endif
	
	function unSupportedS2Auth($s in SlaveType) =
		if( $s=SECURITY_SENSOR_NAT or $s=THERMOSTAT_NAT  or $s=THERMOSTAT_UP or $s=ALARM_NAT  or $s=ALARM_UP )then
			//AUTH_S2_0
			false
		else
			//AUTH_S2_1
			true
		endif
		
	function supportedS2Unauth($s in SlaveType) =
		if( $s=SWITCH_NAT or $s=LIGHT_NAT  or $s=SENSOR_NAT or $s=SECURITY_SENSOR_NAT or $s=THERMOSTAT_NAT
			or $s=THERMOSTAT_UP or $s=ALARM_NAT or $s=ALARM_UP)then
			//UNAUTH_S2_1
			true
		else
			//UNAUTH_S2_0
			false
		endif
	
	function unSupportedS2Unauth($s in SlaveType) =
		if( $s=SWITCH_NAT or $s=LIGHT_NAT  or $s=SENSOR_NAT or $s=SECURITY_SENSOR_NAT or $s=THERMOSTAT_NAT
			or $s=THERMOSTAT_UP or $s=ALARM_NAT or $s=ALARM_UP)then
			//UNAUTH_S2_0
			false
		else
			//UNAUTH_S2_1
			true
		endif
		
	function supportedSkex($s in SlaveType) =
		if( $s=LEGACY_DEVICE)then
			//SKEX_0
			false
		else
			//SKEX_1
			true
		endif
		
	function unSupportedSkex($s in SlaveType) =
		if( $s=LEGACY_DEVICE)then
			//SKEX_1
			true
		else
			//SKEX_0
			false
		endif
	
	function supportedEcdh($s in SlaveType) =
		if( $s=LEGACY_DEVICE)then
			//ECDH_0
			false
		else
			//ECDH_1
			true
		endif
	
	function unSupportedEcdh($s in SlaveType) =
		if( $s=LEGACY_DEVICE)then
			//ECDH_1
			true
		else
			//ECDH_0
			false
		endif
	
		
	function recomposePubKey($p in Boolean,$k in KnowledgeAsymPubKey)=	
		if($p=true and $k=OB_KEY_MITM_CTRL)then
		 	KPUB_MITM_CTRL
		 else
		 	if($p=true and $k=OB_KEY_MITM_SLV)then
		 		KPUB_MITM_SLV
		 	else
		 		if($p=true and $k=OB_KEY_SLV )then
		 			KPUB_SLV
		 		else
		 			if($p=true and $k=OB_KEY_CTRL )then
		 				KPUB_CTRL
		 			else
		 				KPUB_ERR		 				
		 			endif
		 		endif		 	
		 	endif		 							   
		endif
		
	rule r_initEnvCtrl =
		if(controllerState(self) = INIT_CTRL)then
			let($ctype =controller(self)) in
				if($ctype = CONTROLLER_S2)then
					par				
						// csa set to 0 for default max security
						knowsBitString(self,CSA_1):= true
						knowsBitString(self,CSA_0):= false
						knowsBitString(self,SKEX_0):=false
						knowsBitString(self,SKEX_1):= true
						knowsBitString(self,ECDH_0):= false	
						knowsBitString(self,ECDH_1):= true
						knowsBitString(self,ACCESS_S2_0):= false
						knowsBitString(self,ACCESS_S2_1):= true
						knowsBitString(self,AUTH_S2_0):=false
						knowsBitString(self,AUTH_S2_1):= true
						knowsBitString(self,UNAUTH_S2_0):= false
						knowsBitString(self,UNAUTH_S2_1):= true
						knowsBitString(self,SO_0):= false
						knowsBitString(self,SO_1):= true
										
						controllerState(self) := ADD_MODE
					endpar
				endif
			endlet			
		endif

	rule r_initEnvSlv =
		if(slaveState(self) = INIT_SLV)then
			par
							
				let($type = slave(self)) in
					par
						knowsBitString(self,SKEX_1):=supportedSkex($type)
						knowsBitString(self,ECDH_1):=supportedEcdh($type)	
						knowsBitString(self,CSA_1):=supportedCsa($type)
						knowsBitString(self,ACCESS_S2_1):=supportedS2Access($type)
						knowsBitString(self,AUTH_S2_1):=supportedS2Auth($type)
						knowsBitString(self,UNAUTH_S2_1):=supportedS2Unauth($type)
						knowsBitString(self,SKEX_0):=unSupportedSkex($type)
						knowsBitString(self,ECDH_0):=unSupportedEcdh($type)	
						knowsBitString(self,CSA_0):=unSupportedCsa($type)
						knowsBitString(self,ACCESS_S2_0):=unSupportedS2Access($type)
						knowsBitString(self,AUTH_S2_0):=unSupportedS2Auth($type)
						knowsBitString(self,UNAUTH_S2_0):=unSupportedS2Unauth($type)
						
					endpar
				endlet
				knowsBitString(self,SO_1):= true
				knowsBitString(self,SO_0):= false
				//knows(self,SO_0):= false
				slaveState(self) := LEARN_MODE
				startTimer(TB1) := true
			endpar		
		endif

	rule r_timeoutTb1 =
		if(startTimer(TB1))then
			if(slaveState(self) = LEARN_MODE and passed(TB1) ) then			
				slaveState(self) := TIMEOUT_S		
			endif	
		endif
		
	rule r_kexGet =
		if(controllerState(self) = ADD_MODE ) then
			let ($eslv=nodeE)in
				par 
					protocolMessage( self , $eslv ):= KEX_GET
					controllerState(self) := WAIT_KEX_REP
					startTimer(TA1) := true
				endpar	
			endlet		
		endif
		
	rule r_kexGetReplay =
		let ($slv=nodeB,$ctrl=nodeA) in
			if(protocolMessage($ctrl , self) = KEX_GET and protocolMessage( self , $slv )= EMPTY) then				
				protocolMessage( self , $slv ):= KEX_GET						
			endif	
		endlet

	
	rule r_kexReport =
		let ($ectrl=nodeE)in			 
			if(slaveState(self) = LEARN_MODE  and protocolMessage(  $ectrl , self ) = KEX_GET ) then
				if(not(passed(TB1)))then
					par
						slaveState(self) := WAIT_KEX_SET
						protocolMessage(  self, $ectrl ) := KEX_REP
						startTimer(TB2) := true
						startTimer(TB1) := false				
						if(knowsBitString(self,CSA_1))then
							
								messageField(nodeB,nodeE,1,KEX_REP):= CSA_1
								
						else
							
								messageField(nodeB,nodeE,1,KEX_REP):= CSA_0
								
						endif
						if(knowsBitString(self,SKEX_1))then
							
								messageField(nodeB,nodeE,2,KEX_REP):= SKEX_1
								
						else
							
								messageField(nodeB,nodeE,2,KEX_REP):= SKEX_0
								
						endif
						if(knowsBitString(self,ECDH_1))then
							
								messageField(nodeB,nodeE,3,KEX_REP):= ECDH_1
								
						else
							
								messageField(nodeB,nodeE,3,KEX_REP):= ECDH_0
								
						endif
						if(knowsBitString(self,ACCESS_S2_1))then
							
								messageField(nodeB,nodeE,4,KEX_REP):= ACCESS_S2_1
								
						else
							
								messageField(nodeB,nodeE,4,KEX_REP):= ACCESS_S2_0
								
						endif
						if(knowsBitString(self,AUTH_S2_1))then
							
								messageField(nodeB,nodeE,5,KEX_REP):= AUTH_S2_1
								
						else
							
								messageField(nodeB,nodeE,5,KEX_REP):= AUTH_S2_0
								
						endif
						if(knowsBitString(self,UNAUTH_S2_1))then
							
								messageField(nodeB,nodeE,6,KEX_REP):= UNAUTH_S2_1
								
						else
						
								messageField(nodeB,nodeE,6,KEX_REP):= UNAUTH_S2_0
								
						endif
						
						messageField(nodeB,nodeE,7,KEX_REP):= SO_1
						
						
					endpar
				endif
			endif
		endlet
		
	rule r_kexSetCraft =	
		let ($slv=nodeB) in
			if(protocolMessage( $slv , self ) = KEX_REP )then
				par		
					messageArrived := true
					protocolMessage(  self, $slv ) := KEX_SET			
					// KEX SET payload, auto approves all_requested key					
					messageField(nodeE,nodeB,1,KEX_SET):= messageField(nodeB,nodeE,1,KEX_REP)
					messageField(nodeE,nodeB,2,KEX_SET):= messageField(nodeB,nodeE,2,KEX_REP)	
					messageField(nodeE,nodeB,3,KEX_SET):= messageField(nodeB,nodeE,3,KEX_REP)
					messageField(nodeE,nodeB,4,KEX_SET):= messageField(nodeB,nodeE,4,KEX_REP)
					messageField(nodeE,nodeB,5,KEX_SET):= messageField(nodeB,nodeE,5,KEX_REP)	
					messageField(nodeE,nodeB,6,KEX_SET):= messageField(nodeB,nodeE,6,KEX_REP)
					messageField(nodeE,nodeB,7,KEX_SET):= messageField(nodeB,nodeE,7,KEX_REP)	
					
					
				
				endpar
			endif
		endlet
		
	rule r_kexReportReplay =
		let ($ctrl=nodeA, $slv=nodeB) in
			if(protocolMessage(  $ctrl , self ) = KEX_GET  and protocolMessage(  $slv, self ) = KEX_REP  and protocolMessage( self,$ctrl ) != KEX_REP)then
					par
						protocolMessage(  self, $ctrl ) := KEX_REP
						// KEX REPORT payload
						messageField(nodeE,nodeA,1,KEX_REP):=messageField(nodeB,nodeE,1,KEX_REP)
						messageField(nodeE,nodeA,2,KEX_REP):=messageField(nodeB,nodeE,2,KEX_REP)
						messageField(nodeE,nodeA,3,KEX_REP):=messageField(nodeB,nodeE,3,KEX_REP)
						messageField(nodeE,nodeA,4,KEX_REP):=messageField(nodeB,nodeE,4,KEX_REP)
						messageField(nodeE,nodeA,5,KEX_REP):=messageField(nodeB,nodeE,5,KEX_REP)
						messageField(nodeE,nodeA,6,KEX_REP):=messageField(nodeB,nodeE,6,KEX_REP)
						messageField(nodeE,nodeA,7,KEX_REP):=messageField(nodeB,nodeE,7,KEX_REP)
						
					endpar
			endif
		endlet
	
	rule r_kexSetReplay =
		let ($slv=nodeB, $ctrl=nodeA) in
			if(protocolMessage($ctrl , self) = KEX_SET and protocolMessage(self , $slv) = KEX_GET)then
				par		
					
					protocolMessage(  self, $slv ) := KEX_SET			
					// KEX SET payload, auto approves all_requested key					
					messageField(nodeE,nodeB,1,KEX_SET):=messageField(nodeA,nodeE,1,KEX_SET)
					messageField(nodeE,nodeB,2,KEX_SET):=messageField(nodeA,nodeE,2,KEX_SET)
					messageField(nodeE,nodeB,3,KEX_SET):=messageField(nodeA,nodeE,3,KEX_SET)
					messageField(nodeE,nodeB,4,KEX_SET):=messageField(nodeA,nodeE,4,KEX_SET)
					messageField(nodeE,nodeB,5,KEX_SET):=messageField(nodeA,nodeE,5,KEX_SET)
					messageField(nodeE,nodeB,6,KEX_SET):=messageField(nodeA,nodeE,6,KEX_SET)
					messageField(nodeE,nodeB,7,KEX_SET):=messageField(nodeA,nodeE,7,KEX_SET)
					
					
				
				endpar
			endif
		endlet			
		
	rule r_kexReportCraft =
		let ($ctrl=nodeA, $slv=nodeB) in
			if(protocolMessage(  $ctrl , self ) = KEX_GET and messageArrived = true and protocolMessage( self,$ctrl ) != KEX_REP)then
				 if(nearToEnd(TA1))then 
					par
						protocolMessage(  self, $ctrl ) := KEX_REP
						// KEX REPORT payload
						messageField(nodeE,nodeA,1,KEX_REP):=messageField(nodeB,nodeE,1,KEX_REP)
						messageField(nodeE,nodeA,2,KEX_REP):=messageField(nodeB,nodeE,2,KEX_REP)
						messageField(nodeE,nodeA,3,KEX_REP):=messageField(nodeB,nodeE,3,KEX_REP)
						messageField(nodeE,nodeA,4,KEX_REP):=messageField(nodeB,nodeE,4,KEX_REP)
						messageField(nodeE,nodeA,5,KEX_REP):=messageField(nodeB,nodeE,5,KEX_REP)
						messageField(nodeE,nodeA,6,KEX_REP):=messageField(nodeB,nodeE,6,KEX_REP)
						messageField(nodeE,nodeA,7,KEX_REP):=messageField(nodeB,nodeE,7,KEX_REP)
						
					endpar
				endif
			endif
		endlet
		
      rule r_timeoutTa1 =
      		if(startTimer(TA1))then
      			if(controllerState(self) = WAIT_KEX_REP and passed(TA1)) then			
      				controllerState(self) := TIMEOUT_C		
      			endif
      		endif
      		
      rule r_timeoutTia1 =
      		if(startTimer(TAI1))then
      			if( (controllerState(self) = WAIT_EVAL_KEX_KEY or controllerState(self) = WAIT_EVAL_KEX_SCHEME or controllerState(self) = WAIT_EVAL_KEX_CURVE or controllerState(self) = WAIT_EVAL_CSA) and passed(TAI1)) then			
      				controllerState(self) := TIMEOUT_C		
      			endif
			endif	

     rule r_setEvalKexKey=
      	let ($eslv=nodeE) in
      		if(controllerState(self) = WAIT_KEX_REP  and protocolMessage($eslv , self) = KEX_REP )then
				if(not(passed(TA1)))then
	      			par				
						controllerState(self) := WAIT_EVAL_KEX_KEY
						startTimer(TAI1) := true
						startTimer(TA1) := false
					endpar
				endif
      		endif
      	endlet
     		
	rule r_evalReqKey=
     	 let ($eslv=nodeE) in
	     	 if(controllerState(self) = WAIT_EVAL_KEX_KEY  and protocolMessage($eslv,self) = KEX_REP 
	     	 	and (knowsBitString(self,messageField(nodeE,nodeA,4,KEX_REP))=true or knowsBitString(self,messageField(nodeE,nodeA,5,KEX_REP))=true
	 	 		or knowsBitString(self,messageField(nodeE,nodeA,6,KEX_REP))=true or knowsBitString(self,messageField(nodeE,nodeA,7,KEX_REP))=true)) then
	 	 		if(not(passed(TAI1)))then
		 	 		
						controllerState(self) := WAIT_EVAL_KEX_SCHEME				
						
				endif
	     	 endif
		 endlet

		rule r_failEvalReqKey=
     	 let ($eslv=nodeE) in
	     	 if(controllerState(self) = WAIT_EVAL_KEX_KEY  and protocolMessage($eslv,self) = KEX_REP 
	     	 	and not (knowsBitString(self,messageField(nodeE,nodeA,4,KEX_REP))=true or knowsBitString(self,messageField(nodeE,nodeA,5,KEX_REP))=true
	 	 		or knowsBitString(self,messageField(nodeE,nodeA,6,KEX_REP))=true or knowsBitString(self,messageField(nodeE,nodeA,7,KEX_REP))=true)) then
	 	 		if(not(passed(TAI1)))then
		 	 		par
						protocolMessage(  self , $eslv ) := KEX_FAIL_KEX_KEY
						controllerState(self) := ERROR_C
					endpar
				endif
	     	 endif
     	 endlet
     
	rule r_evalReqScheme=
     	 let ($eslv=nodeE) in 
     	 	if(controllerState(self) = WAIT_EVAL_KEX_SCHEME and protocolMessage(  $eslv , self ) = KEX_REP and messageField(nodeE,nodeA,2,KEX_REP)=SKEX_1 ) then
				if(not(passed(TAI1)))then
					
						controllerState(self) := WAIT_EVAL_KEX_CURVE
						
				endif
			endif
		endlet
    
	rule r_failEvalReqScheme=
     	 let ($eslv=nodeE) in 
     	 	if(controllerState(self) = WAIT_EVAL_KEX_SCHEME and protocolMessage($eslv , self) = KEX_REP and messageField(nodeE,nodeA,2,KEX_REP)=SKEX_0 ) then
				if(not(passed(TAI1)))then
					par
						protocolMessage(  self , $eslv ) := KEX_FAIL_KEX_SCHEME
						controllerState(self) := ERROR_C					
					endpar
				endif
			endif
		endlet	
		
	rule r_evalReqCurve=
     	 let ($eslv=nodeE) in 
     	 	if(controllerState(self) = WAIT_EVAL_KEX_CURVE and protocolMessage($eslv , self) = KEX_REP and messageField(nodeE,nodeA,3,KEX_REP)=ECDH_1 ) then
				if(not(passed(TAI1)))then
					
						controllerState(self) := WAIT_EVAL_CSA
						
				endif
			endif
		endlet
      
	rule r_failEvalReqCurve=
     	 let ($eslv=nodeE) in 
     	 	if(controllerState(self) = WAIT_EVAL_KEX_CURVE and protocolMessage($eslv , self) = KEX_REP and messageField(nodeE,nodeA,3,KEX_REP)=ECDH_0 ) then
				if(not(passed(TAI1)))then
					par
						protocolMessage(  self , $eslv ) := KEX_FAIL_KEX_CURVE
						controllerState(self) := ERROR_C					
					endpar
				endif
			endif
		endlet 
		
	rule r_evalReqCsa=
		let ($eslv=nodeE) in 
     	 	if(controllerState(self) = WAIT_EVAL_CSA and protocolMessage($eslv,self) = KEX_REP  and messageField(nodeE,nodeA,1,KEX_REP)=CSA_0) then
				if(not(passed(TAI1)))then
				
						controllerState(self) := WAIT_ECDH_PUB_JOIN						
				
				endif
			endif
		endlet 
	 	
	rule r_failEvalReqCsa=
		let ($eslv=nodeE) in 
     	 	if(controllerState(self) = WAIT_EVAL_CSA and protocolMessage($eslv,self) = KEX_REP  and messageField(nodeE,nodeA,1,KEX_REP)=CSA_1) then
				let($csa = userCsa(self)) in 
					if(not(passed(TAI1)) and $csa=true )then
					
							controllerState(self) := WAIT_ECDH_PUB_JOIN						
						
					else
						if(not(passed(TAI1)) and $csa!=true )then
							par
								controllerState(self) := ERROR_C
								protocolMessage( self , $eslv ) := KEX_FAIL_CANCEL						
							endpar
						endif
					endif
				endlet
			endif
		endlet 
	
	rule r_evalKexReport =
      	par
	      	r_setEvalKexKey[]
	      	r_evalReqKey[]
	      	r_failEvalReqKey[]
	      	r_evalReqScheme[]
	      	r_failEvalReqScheme[]
	      	r_evalReqCurve[]
	      	r_failEvalReqCurve[]
	      	r_evalReqCsa[]
	      	r_failEvalReqCsa[]
		endpar
		
	rule r_timeoutTa2 =
		if(startTimer(TA2))then
			if(controllerState(self) = WAIT_ECDH_PUB_JOIN and passed(TA2)) then			
				controllerState(self) := TIMEOUT_C		
			endif
		endif
		

	rule r_kexSet =
		let ($eslv=nodeE) in
			if(controllerState(self) = WAIT_ECDH_PUB_JOIN and protocolMessage($eslv,self) = KEX_REP and not(protocolMessage( self, $eslv ) = KEX_SET))then
				if(not(passed(TAI1)))then
					par
						protocolMessage( self, $eslv ) := KEX_SET					
						startTimer(TA2) := true
						startTimer(TAI1) := false
						                                                     
						messageField(nodeA,nodeE,1,KEX_SET):=messageField(nodeE,nodeA,1,KEX_REP)
						messageField(nodeA,nodeE,2,KEX_SET):=messageField(nodeE,nodeA,2,KEX_REP)
						messageField(nodeA,nodeE,3,KEX_SET):=messageField(nodeE,nodeA,3,KEX_REP)
						
						
						if(messageField(nodeE,nodeA,4,KEX_REP)=ACCESS_S2_1 and userGrantS2Access)then
							
								messageField(nodeA,nodeE,4,KEX_SET):=ACCESS_S2_1
								
						else		
							
								messageField(nodeA,nodeE,4,KEX_SET):=ACCESS_S2_0
								
						endif
						if(messageField(nodeE,nodeA,5,KEX_REP)=AUTH_S2_1 and userGrantS2Auth)then
							
								messageField(nodeA,nodeE,5,KEX_SET):=AUTH_S2_1
								
						else		
							
								messageField(nodeA,nodeE,5,KEX_SET):=AUTH_S2_0
								
						endif
						if(messageField(nodeE,nodeA,6,KEX_REP)=UNAUTH_S2_1 and userGrantS2Unauth)then
							
								messageField(nodeA,nodeE,6,KEX_SET):=UNAUTH_S2_1
								
						else		
							
								messageField(nodeA,nodeE,6,KEX_SET):=UNAUTH_S2_0
								
						endif
						if(messageField(nodeE,nodeA,7,KEX_REP)=SO_1 and userGrantS0)then
							
								messageField(nodeA,nodeE,7,KEX_SET):=SO_1
								
						else		
							
								messageField(nodeA,nodeE,7,KEX_SET):=SO_0
								
						endif	
					endpar
				endif
			endif
		endlet
		
		
	rule r_timeoutTb2 =
		if(startTimer(TB2))then
			if(slaveState(self) = WAIT_KEX_SET and passed(TB2)) then			
				slaveState(self) := TIMEOUT_S		
			endif
		endif


    rule r_setEvalSetKexKey=
		let ($ectrl=nodeE) in
			if(slaveState(self) = WAIT_KEX_SET and protocolMessage(  $ectrl , self ) = KEX_SET) then
				if(not(passed(TB2)))then
					par
						slaveState(self) := WAIT_EVAL_SET_KEX_KEY
						startTimer(TB2) := false
					endpar
				endif
			endif
		endlet
		
	rule r_evalGrantKey=
		let ($ectrl=nodeE) in
			if(slaveState(self) = WAIT_EVAL_SET_KEX_KEY  and protocolMessage(  $ectrl , self ) = KEX_SET and
				((messageField(nodeE,nodeB,4,KEX_SET) = messageField(nodeB,nodeE,4,KEX_REP) or (messageField(nodeB,nodeE,4,KEX_REP)=ACCESS_S2_1 and messageField(nodeE,nodeB,4,KEX_SET)=ACCESS_S2_0))
					and (messageField(nodeE,nodeB,5,KEX_SET) = messageField(nodeB,nodeE,5,KEX_REP) or (messageField(nodeB,nodeE,5,KEX_REP)=AUTH_S2_1 and messageField(nodeE,nodeB,5,KEX_SET)=AUTH_S2_0))
					and (messageField(nodeE,nodeB,6,KEX_SET) = messageField(nodeB,nodeE,6,KEX_REP) or (messageField(nodeB,nodeE,6,KEX_REP)=UNAUTH_S2_1 and messageField(nodeE,nodeB,6,KEX_SET)=UNAUTH_S2_0))
					and (messageField(nodeE,nodeB,7,KEX_SET) = messageField(nodeB,nodeE,7,KEX_REP) or (messageField(nodeB,nodeE,7,KEX_REP)=SO_1 and messageField(nodeE,nodeB,7,KEX_SET)=SO_0))))then
					
						slaveState(self) := WAIT_EVAL_SET_KEX_SCHEME
						
			endif
		endlet
		

	rule r_failEvalGrantKey=
		let ($ectrl=nodeE) in
			if(slaveState(self) = WAIT_EVAL_SET_KEX_KEY  and protocolMessage(  $ectrl , self ) = KEX_SET and
				not((messageField(nodeE,nodeB,4,KEX_SET) = messageField(nodeB,nodeE,4,KEX_REP) or (messageField(nodeB,nodeE,4,KEX_REP)=ACCESS_S2_1 and messageField(nodeE,nodeB,4,KEX_SET)=ACCESS_S2_0))
					and (messageField(nodeE,nodeB,5,KEX_SET) = messageField(nodeB,nodeE,5,KEX_REP) or (messageField(nodeB,nodeE,5,KEX_REP)=AUTH_S2_1 and messageField(nodeE,nodeB,5,KEX_SET)=AUTH_S2_0))
					and (messageField(nodeE,nodeB,6,KEX_SET) = messageField(nodeB,nodeE,6,KEX_REP) or (messageField(nodeB,nodeE,6,KEX_REP)=UNAUTH_S2_1 and messageField(nodeE,nodeB,6,KEX_SET)=UNAUTH_S2_0))
					and (messageField(nodeE,nodeB,7,KEX_SET) = messageField(nodeB,nodeE,7,KEX_REP) or (messageField(nodeB,nodeE,7,KEX_REP)=SO_1 and messageField(nodeE,nodeB,7,KEX_SET)=SO_0))))then
					par
						protocolMessage(  self , $ectrl ) := KEX_FAIL_KEX_KEY
						slaveState(self) := ERROR_S
					endpar
			endif
		endlet

	rule r_evalGrantScheme=
		let ($ectrl=nodeE) in
			if(slaveState(self) = WAIT_EVAL_SET_KEX_SCHEME and protocolMessage(  $ectrl , self ) = KEX_SET and messageField(nodeE,nodeB,2,KEX_SET)=SKEX_1)then
				
					slaveState(self) := WAIT_EVAL_SET_KEX_CURVE
					
			endif	
		endlet	
				
	rule r_failEvalGrantScheme=
		let ($ectrl=nodeE) in
			if(slaveState(self) = WAIT_EVAL_SET_KEX_SCHEME  and protocolMessage(  $ectrl , self ) = KEX_SET and messageField(nodeE,nodeB,2,KEX_SET)=SKEX_0)then
				par
					protocolMessage(  self , $ectrl ) := KEX_FAIL_KEX_SCHEME
					slaveState(self) := ERROR_S
				endpar
			endif	
		endlet	
		
	rule r_evalGrantCurve=
		let ($ectrl=nodeE) in
			if(slaveState(self) = WAIT_EVAL_SET_KEX_CURVE  and protocolMessage(  $ectrl , self ) = KEX_SET and messageField(nodeE,nodeB,3,KEX_SET)=ECDH_1)then
				
					slaveState(self) := WAIT_EVAL_SET_CSA	
					
			
			endif	
		endlet
	
	rule r_failEvalGrantCurve=
		let ($ectrl=nodeE) in
			if(slaveState(self) = WAIT_EVAL_SET_KEX_CURVE  and protocolMessage(  $ectrl , self ) = KEX_SET and messageField(nodeE,nodeB,3,KEX_SET)=ECDH_0)then
				par
					protocolMessage(  self , $ectrl ) := KEX_FAIL_KEX_CURVE
					slaveState(self) := ERROR_S
				endpar
			endif	
		endlet	
		
	rule r_evalGrantCsa=
		let ($ectrl=nodeE) in
			if(slaveState(self) = WAIT_EVAL_SET_CSA  and protocolMessage($ectrl,self) = KEX_SET and messageField(nodeE,nodeB,1,KEX_SET)=messageField(nodeB,nodeE,1,KEX_REP))then
				
					slaveState(self) := WAIT_ECDH_PUB_CTRL		
					
			endif	
		endlet	
		
	rule r_failEvalGrantCsa=
		let ($ectrl=nodeE) in
			if(slaveState(self) = WAIT_EVAL_SET_CSA  and protocolMessage($ectrl,self) = KEX_SET and messageField(nodeE,nodeB,1,KEX_SET)!=messageField(nodeB,nodeE,1,KEX_REP))then
				par
					slaveState(self) := ERROR_S
					protocolMessage( self , $ectrl ) := KEX_FAIL_KEX_KEY
				endpar
			endif	
		endlet
	
	rule r_evalKexSet =
		par
	      	r_setEvalSetKexKey[]
	      	r_evalGrantKey[]
	      	r_failEvalGrantKey[]
	      	r_evalGrantScheme[]
	      	r_failEvalGrantScheme[]
	      	r_evalGrantCurve[]
	      	r_failEvalGrantCurve[]
	      	r_evalGrantCsa[]
	      	r_failEvalGrantCsa[]
		endpar
		
		
	rule r_timeoutTb3 =
		if(startTimer(TB3))then
			if(slaveState(self) = WAIT_ECDH_PUB_CTRL and passed(TB3))then
				slaveState(self) := TIMEOUT_S
			endif
		endif
		
	rule r_sendSlvPubKey =
		let ($ectrl=nodeE) in
			if(slaveState(self) = WAIT_ECDH_PUB_CTRL and protocolMessage($ectrl,self) = KEX_SET )then
				par
					protocolMessage( self, $ectrl ) := PUB_KEY_REP_JOIN
					startTimer(TB3) := true
					if(messageField(nodeE,nodeB,1,KEX_SET) = CSA_1 )then												
						messageField(nodeB,nodeE,1,PUB_KEY_REP_JOIN) := KPUB_SLV//readKnowledge(self,KPUB_SLV)	
					else 
						messageField(nodeB,nodeE,1,PUB_KEY_REP_JOIN) := OB_KEY_SLV//readKnowledge(self,OB_KEY_SLV)															
					endif
				endpar
			endif
		endlet
		
	rule r_sendEctrlKey =
		let ($slv=nodeB) in
			if(protocolMessage( $slv , self ) = PUB_KEY_REP_JOIN and messageField(nodeB,nodeE,1,PUB_KEY_REP_JOIN) = OB_KEY_SLV)then
				par					
					protocolMessage( self , $slv ) := PUB_KEY_REP_CTRL
					messageField(nodeE,nodeB,1,PUB_KEY_REP_CTRL) := KPUB_MITM_CTRL//readKnowledge(self,KPUB_MITM_CTRL)
					
				endpar
			endif
		endlet
		
	rule r_sendEslvKey = 
		let ($ctrl=nodeA) in
			if(protocolMessage( $ctrl , self ) = KEX_SET and knowsBitString(self,PIN_OK)=true)then
				par
					protocolMessage( self, $ctrl ) := PUB_KEY_REP_JOIN
					messageField(nodeE,nodeA,1,PUB_KEY_REP_JOIN) := OB_KEY_MITM_SLV//readKnowledge(self,OB_KEY_MITM_SLV)						
				endpar
			endif
		endlet
		
		
	rule r_sendSlvPubKeyReplay = 
		let ($ctrl=nodeA, $slv=nodeB) in
			if(protocolMessage( $ctrl , self ) = KEX_SET and protocolMessage($slv , self) = PUB_KEY_REP_JOIN and protocolMessage( self , $ctrl ) != PUB_KEY_REP_JOIN)then
				par
					protocolMessage( self, $ctrl ) := PUB_KEY_REP_JOIN
					if(messageField(nodeA,nodeE,1,KEX_SET)=CSA_0)then
						par
							knowsAsymPubKey(self,messageField(nodeE,nodeA,1,PUB_KEY_REP_JOIN)):=true
							messageField(nodeE,nodeA,1,PUB_KEY_REP_JOIN):=messageField(nodeB,nodeE,1,PUB_KEY_REP_JOIN)
						endpar
					else
						par
							knowsAsymPubKey(self,messageField(nodeE,nodeA,1,PUB_KEY_REP_JOIN)):=true
							messageField(nodeE,nodeA,1,PUB_KEY_REP_JOIN):=messageField(nodeB,nodeE,1,PUB_KEY_REP_JOIN)
						endpar
					endif
				endpar
			endif
		endlet
	
	rule r_sendCtrlPubKeyReplay = 
		let ($ctrl=nodeA, $slv=nodeB) in
			if(protocolMessage( $ctrl , self ) = PUB_KEY_REP_CTRL and protocolMessage( $slv , self ) = PUB_KEY_REP_JOIN and protocolMessage( self , $slv ) != PUB_KEY_REP_CTRL)then
				par
					protocolMessage( self, $slv ) := PUB_KEY_REP_CTRL
					if(messageField(nodeA,nodeE,1,KEX_SET)=CSA_0)then
						par
							knowsAsymPubKey(self,messageField(nodeE,nodeB,1,PUB_KEY_REP_CTRL)):=true
							messageField(nodeE,nodeB,1,PUB_KEY_REP_CTRL) := messageField(nodeA,nodeE,1,PUB_KEY_REP_CTRL)
						endpar
					else
						par
							knowsAsymPubKey(self,messageField(nodeE,nodeB,1,PUB_KEY_REP_CTRL)):=true
							messageField(nodeE,nodeB,1,PUB_KEY_REP_CTRL) := messageField(nodeA,nodeE,1,PUB_KEY_REP_CTRL)
						endpar
					endif
				endpar
			endif
		endlet
		
		
	rule r_timeoutTia2 =
		if(startTimer(TAI2))then
			if((controllerState(self) = INSERT_PIN or controllerState(self) = WAIT_NONCE or controllerState(self) = WAIT_SEI_KEX_SET_ECHO) and passed(TAI2)) then			
				controllerState(self) := TIMEOUT_C	
			endif
		endif

	rule r_insertPin =
		let ($eslv=nodeE) in
			if(controllerState(self) = WAIT_ECDH_PUB_JOIN  and protocolMessage( $eslv ,self ) = PUB_KEY_REP_JOIN ) then
				if(not(passed(TA2)))then 
					par
						controllerState(self) := INSERT_PIN
						startTimer(TAI2) := true
						startTimer(TA2) := false
						abortCtrlSaved := ctrlAbort
					endpar	
				endif
			else				
				if(controllerState(self) = INSERT_PIN and  messageField(nodeA,nodeE,1,KEX_SET)=CSA_0 and protocolMessage( $eslv ,self ) = PUB_KEY_REP_JOIN and abortCtrlSaved = false) then
					if(not(passed(TAI2)))then
						let($sk_ob =messageField(nodeE,nodeA,1,PUB_KEY_REP_JOIN))in
							par
								controllerState(self) := WAIT_NONCE
								protocolMessage( self , $eslv ) := PUB_KEY_REP_CTRL
								messageField(nodeA,nodeE,1,PUB_KEY_REP_CTRL) := KPUB_CTRL//readKnowledge(self,KPUB_CTRL)
								if(qrCodeUseDecison= true)then								
									let($pubkey_qr=qrKey)in
										let($aes_qr=diffieHellman($pubkey_qr,KPRIV_CTRL))in
											par
												knowsSymKey(self,$aes_qr):=true
												if(recomposePubKey(true,$sk_ob)=$pubkey_qr)then
													par
														knowsBitString(self,PIN_OK):=true
														knowsBitString(self,PIN_ERROR):=false
													endpar
												endif
											endpar
										endlet
									endlet
										
								else
									if(pinCode = true) then
										par
											let($pub=recomposePubKey(true,$sk_ob))in
												let($aes_0=diffieHellman($pub,KPRIV_CTRL))in
														knowsSymKey(self,$aes_0):=true
												endlet
											endlet
											knowsBitString(self,PIN_OK):=true
											knowsBitString(self,PIN_ERROR):=false
										endpar
									else
										if(pinCode = false) then
											par
												let($pub_e=recomposePubKey(false,$sk_ob))in
													let($aes_e=diffieHellman($pub_e,KPRIV_CTRL))in
															knowsSymKey(self,$aes_e):=true
													endlet
												endlet
												knowsBitString(self,PIN_OK):=false
												knowsBitString(self,PIN_ERROR):=true
											endpar
										endif
									endif
								endif
							endpar
						endlet
					endif
				else
					if(controllerState(self) = INSERT_PIN and  messageField(nodeA,nodeE,1,KEX_SET)=CSA_1 and protocolMessage( $eslv ,self ) = PUB_KEY_REP_JOIN and abortCtrlSaved = false) then
						if(not(passed(TAI2)))then
							let($sk =messageField(nodeE,nodeA,1,PUB_KEY_REP_JOIN))in
								let($aes_1=diffieHellman($sk,KPRIV_CTRL))in
									par
										controllerState(self) := WAIT_NONCE
										protocolMessage( self , $eslv ) := PUB_KEY_REP_CTRL
										messageField(nodeA,nodeE,1,PUB_KEY_REP_CTRL) := OB_KEY_CTRL	
										knowsSymKey(self,$aes_1):=true
									endpar
								endlet
							endlet
						endif
					else
						if(controllerState(self) = INSERT_PIN and protocolMessage( $eslv ,self ) = PUB_KEY_REP_JOIN and abortCtrlSaved = true)then
							if(not(passed(TAI2)))then
								par
									controllerState(self) := ERROR_C
									protocolMessage( self , $eslv ) := KEX_FAIL_CANCEL
								endpar
							endif
						endif			
					endif
				endif	
			endif
		endlet

	rule r_timeoutTib1 =
		if(startTimer(TBI1))then
			if((slaveState(self) = INSERT_PIN_CSA or slaveState(self) = WAIT_NONCE_REP_REI or slaveState(self) = WAIT_KEX_REPORT_ECHO) and passed(TBI1))then
				slaveState(self) := TIMEOUT_S
			endif
		endif
		
	rule r_insertPinCsa =
		let ($ectrl=nodeE) in
			if(slaveState(self) = WAIT_ECDH_PUB_CTRL and  protocolMessage( $ectrl ,self ) = PUB_KEY_REP_CTRL)then
				if(not(passed(TB3)))then
					par				
						slaveState(self) := INSERT_PIN_CSA
						startTimer(TBI1) := true
						startTimer(TB3) := false
						abortSlvSaved := slvAbort
						
					endpar	
				endif
			else
			
				if(slaveState(self) = INSERT_PIN_CSA and messageField(nodeE,nodeB,1,KEX_SET)=CSA_0 and protocolMessage( $ectrl ,self ) = PUB_KEY_REP_CTRL and abortSlvSaved = false) then
							if(not(passed(TBI1)))then
								let($skc=messageField(nodeE,nodeB,1,PUB_KEY_REP_CTRL))in
									let($aes_0=diffieHellman($skc,KPRIV_SLV))in
										par
											//slaveState(self) := WAIT_SLV_AES
											protocolMessage( self , $ectrl ) := NONCE_GET						
											slaveState(self) := WAIT_NONCE_REP_REI
											knowsSymKey(self,$aes_0):=true												
										endpar
									endlet
								endlet
							endif
						else
							if(slaveState(self) = INSERT_PIN_CSA and messageField(nodeE,nodeB,1,KEX_SET)=CSA_1 and protocolMessage( $ectrl ,self ) = PUB_KEY_REP_CTRL and abortSlvSaved = false) then
								if(not(passed(TBI1)))then
										let($skcob=messageField(nodeE,nodeB,1,PUB_KEY_REP_CTRL))in
											par
												slaveState(self) := WAIT_NONCE_REP_REI
												protocolMessage( self , $ectrl ) := NONCE_GET	
												if(pinCode = true) then
													par
														let($pub=recomposePubKey(true,$skcob))in
															let($aes_1=diffieHellman($pub,KPRIV_SLV))in
																	knowsSymKey(self,$aes_1):=true
															endlet
														endlet
														knowsBitString(self,PIN_OK):=true
														knowsBitString(self,PIN_ERROR):=false
													endpar
												else
													par
														let($pub_e=recomposePubKey(false,$skcob))in
															let($aes_e=diffieHellman($pub_e,KPRIV_SLV))in
																	knowsSymKey(self,$aes_e):=true
															endlet
														endlet
														knowsBitString(self,PIN_OK):=false
														knowsBitString(self,PIN_ERROR):=true
													endpar
												endif	
											endpar
										endlet
								endif
							else
							if(slaveState(self) = INSERT_PIN_CSA and protocolMessage( $ectrl ,self ) = PUB_KEY_REP_CTRL and abortSlvSaved = true)then
								if(not(passed(TBI1)))then
									par
										slaveState(self) := ERROR_S
										protocolMessage( self , $ectrl ) := KEX_FAIL_CANCEL
									endpar
								endif
							endif	
						endif
					endif
			endif
		endlet

	rule r_nonceGetCraft =
		let ($ctrl=nodeA) in
			if(protocolMessage( $ctrl ,self ) = PUB_KEY_REP_CTRL)then
				par
					
					knowsAsymPubKey(self,messageField(nodeA,nodeE,1,PUB_KEY_REP_CTRL)):=true
					protocolMessage( self , $ctrl ) := NONCE_GET
				endpar
			endif
		endlet	
		
	rule r_nonceGetReplay =
		let ($ctrl=nodeA, $slv=nodeB) in
			if(protocolMessage( $slv ,self ) = NONCE_GET and protocolMessage( $ctrl ,self ) = PUB_KEY_REP_CTRL and  protocolMessage( self ,$ctrl ) != NONCE_GET)then
				
					protocolMessage( self , $ctrl ) := NONCE_GET
				
			endif
		endlet
		
	rule r_nonceReport =
		let ($eslv=nodeE) in
			if(controllerState(self) = WAIT_NONCE and protocolMessage( $eslv ,self ) = NONCE_GET)then
				if(not(passed(TAI2)))then
					par
						controllerState(self) := WAIT_SEI_KEX_SET_ECHO
						protocolMessage( self , $eslv ) := NONCE_REPORT					
					endpar
				endif
			endif
		endlet
	
	rule r_nonceReportCraft =
		let ($slv=nodeB) in
			if(protocolMessage( $slv ,self ) = NONCE_GET)then				
					protocolMessage( self , $slv ) := NONCE_REPORT
			endif
		endlet
	
	rule r_nonceReportReplay =
		let ($slv=nodeB,$ctrl=nodeA) in
			if(protocolMessage( $ctrl ,self ) = NONCE_REPORT and protocolMessage( $slv ,self ) = NONCE_GET and protocolMessage( self ,$slv ) != NONCE_REPORT)then				
					protocolMessage( self , $slv ) := NONCE_REPORT
			endif
		endlet	
		
	rule r_SPANestablishment =
		let ($ectrl=nodeE) in
			if(slaveState(self) = WAIT_NONCE_REP_REI and protocolMessage( $ectrl ,self ) = NONCE_REPORT)then
				if(not(passed(TBI1)))then
					par
						if(knowsSymKey(self,KT2)=true)then
							symEnc(EC_SEI_KEX_SET_ECHO,1,1,7):=KT2
						endif
						if(knowsSymKey(self,KT3)=true)then
							symEnc(EC_SEI_KEX_SET_ECHO,1,1,7):=KT3
						endif
						if(knowsSymKey(self,KT_ERROR)=true)then
							symEnc(EC_SEI_KEX_SET_ECHO,1,1,7):=KT_ERROR
						endif
						messageField(nodeB,nodeE,1,EC_SEI_KEX_SET_ECHO):=messageField(nodeE,nodeB,1,KEX_SET)
						messageField(nodeB,nodeE,2,EC_SEI_KEX_SET_ECHO):=messageField(nodeE,nodeB,2,KEX_SET)
						messageField(nodeB,nodeE,3,EC_SEI_KEX_SET_ECHO):=messageField(nodeE,nodeB,3,KEX_SET)
						messageField(nodeB,nodeE,4,EC_SEI_KEX_SET_ECHO):=messageField(nodeE,nodeB,4,KEX_SET)
						messageField(nodeB,nodeE,5,EC_SEI_KEX_SET_ECHO):=messageField(nodeE,nodeB,5,KEX_SET)
						messageField(nodeB,nodeE,6,EC_SEI_KEX_SET_ECHO):=messageField(nodeE,nodeB,6,KEX_SET)
						messageField(nodeB,nodeE,7,EC_SEI_KEX_SET_ECHO):=messageField(nodeE,nodeB,7,KEX_SET)
						protocolMessage( self , $ectrl ) := EC_SEI_KEX_SET_ECHO
						slaveState(self) := WAIT_KEX_REPORT_ECHO		
					endpar
				endif
			endif
		endlet
		
	rule  r_bruteForce=
		let ($slv=nodeB) in
			if(protocolMessage( $slv , self ) = EC_SEI_KEX_SET_ECHO and protocolMessage(  self, $slv) != EC_KEX_REPORT_ECHO  and cracked=false)then
				let($k=KPRIV_MITM_CTRL,$skc =messageField(nodeB,nodeE,1,PUB_KEY_REP_JOIN))in
					
						if(not nearToEnd(TA2)) then
							par
								knowsBitString(self,PIN_OK):=true
								let($pub=recomposePubKey(true,$skc))in
									let($aes_0=diffieHellman($pub,$k))in
											knowsSymKey(self,$aes_0):=true
									endlet
								endlet
								cracked:=true
							endpar
						else
							par
								knowsBitString(self,PIN_ERROR):=true
								let($pub_e=recomposePubKey(false,$skc))in
										let($aes_e=diffieHellman($pub_e,$k))in
												knowsSymKey(self,$aes_e):=true
										endlet
								endlet
								cracked:=true
							endpar
						endif
					
				endlet
			endif			
		endlet
	
	rule r_SPANCraft =
		let ($ctrl=nodeA) in
			if(protocolMessage( $ctrl , self ) = NONCE_REPORT)then
				let($kpriv = KPRIV_MITM_SLV,$skc = messageField(nodeA,nodeE,1,PUB_KEY_REP_CTRL)) in	
					let($aes_0=diffieHellman($skc,$kpriv))in
						par
							knowsSymKey(self,$aes_0):=true
							symEnc(EC_SEI_KEX_SET_ECHO,1,1,7):=$aes_0
							protocolMessage( self , $ctrl ) := EC_SEI_KEX_SET_ECHO
							messageField(nodeE,nodeA,1,EC_SEI_KEX_SET_ECHO):=messageField(nodeA,nodeE,1,KEX_SET)
							messageField(nodeE,nodeA,2,EC_SEI_KEX_SET_ECHO):=messageField(nodeA,nodeE,2,KEX_SET)
							messageField(nodeE,nodeA,3,EC_SEI_KEX_SET_ECHO):=messageField(nodeA,nodeE,3,KEX_SET)
							messageField(nodeE,nodeA,4,EC_SEI_KEX_SET_ECHO):=messageField(nodeA,nodeE,4,KEX_SET)
							messageField(nodeE,nodeA,5,EC_SEI_KEX_SET_ECHO):=messageField(nodeA,nodeE,5,KEX_SET)
							messageField(nodeE,nodeA,6,EC_SEI_KEX_SET_ECHO):=messageField(nodeA,nodeE,6,KEX_SET)
							messageField(nodeE,nodeA,7,EC_SEI_KEX_SET_ECHO):=messageField(nodeA,nodeE,7,KEX_SET)
						endpar
					endlet
				endlet	
			endif
		endlet
		
		
	rule r_SPANReplay =
		let ($ctrl=nodeA,$slv=nodeB) in
			if(protocolMessage($slv , self) = EC_SEI_KEX_SET_ECHO and protocolMessage($ctrl , self) = NONCE_REPORT and protocolMessage(self , $ctrl) != EC_SEI_KEX_SET_ECHO )then
				par
					protocolMessage( self , $ctrl ) := EC_SEI_KEX_SET_ECHO
					messageField(nodeE,nodeA,1,EC_SEI_KEX_SET_ECHO):=messageField(nodeB,nodeE,1,EC_SEI_KEX_SET_ECHO)
					messageField(nodeE,nodeA,2,EC_SEI_KEX_SET_ECHO):=messageField(nodeB,nodeE,2,EC_SEI_KEX_SET_ECHO)
					messageField(nodeE,nodeA,3,EC_SEI_KEX_SET_ECHO):=messageField(nodeB,nodeE,3,EC_SEI_KEX_SET_ECHO)
					messageField(nodeE,nodeA,4,EC_SEI_KEX_SET_ECHO):=messageField(nodeB,nodeE,4,EC_SEI_KEX_SET_ECHO)
					messageField(nodeE,nodeA,5,EC_SEI_KEX_SET_ECHO):=messageField(nodeB,nodeE,5,EC_SEI_KEX_SET_ECHO)
					messageField(nodeE,nodeA,6,EC_SEI_KEX_SET_ECHO):=messageField(nodeB,nodeE,6,EC_SEI_KEX_SET_ECHO)
					messageField(nodeE,nodeA,7,EC_SEI_KEX_SET_ECHO):=messageField(nodeB,nodeE,7,EC_SEI_KEX_SET_ECHO)
				endpar
			endif
		endlet
	
	rule r_evalkexSetEcho =
		let ($eslv=nodeE) in
			if(controllerState(self) = WAIT_SEI_KEX_SET_ECHO and protocolMessage( $eslv ,self ) = EC_SEI_KEX_SET_ECHO)then
				if(not(passed(TAI2)))then
					par
						startTimer(TAI2) := false
						if(symDec(EC_SEI_KEX_SET_ECHO,1,1,7,self)=true and symEnc(EC_SEI_KEX_SET_ECHO,1,1,7)!=KT_ERROR)then
							if(messageField(nodeA,nodeE,1,KEX_SET)=messageField(nodeE,nodeA,1,EC_SEI_KEX_SET_ECHO) and messageField(nodeA,nodeE,2,KEX_SET)=messageField(nodeE,nodeA,2,EC_SEI_KEX_SET_ECHO)
								and messageField(nodeA,nodeE,3,KEX_SET)=messageField(nodeE,nodeA,3,EC_SEI_KEX_SET_ECHO) and messageField(nodeA,nodeE,4,KEX_SET)=messageField(nodeE,nodeA,4,EC_SEI_KEX_SET_ECHO)
								and messageField(nodeA,nodeE,5,KEX_SET)=messageField(nodeE,nodeA,5,EC_SEI_KEX_SET_ECHO) and messageField(nodeA,nodeE,6,KEX_SET)=messageField(nodeE,nodeA,6,EC_SEI_KEX_SET_ECHO)
								and messageField(nodeA,nodeE,7,KEX_SET)=messageField(nodeE,nodeA,7,EC_SEI_KEX_SET_ECHO))then
								par
									controllerState(self) := OK_C
									protocolMessage( self , $eslv ) := EC_KEX_REPORT_ECHO
									if(knowsSymKey(self,KT1)=true)then
										symEnc(EC_KEX_REPORT_ECHO,1,1,7):=KT1
									endif
									if(knowsSymKey(self,KT3)=true)then
										symEnc(EC_KEX_REPORT_ECHO,1,1,7):=KT3
									endif
									if(knowsSymKey(self,KT_ERROR)=true)then
										symEnc(EC_KEX_REPORT_ECHO,1,1,7):=KT_ERROR
									endif              
									messageField(nodeA,nodeE,1,EC_KEX_REPORT_ECHO):=messageField(nodeE,nodeA,1,KEX_REP)
									messageField(nodeA,nodeE,2,EC_KEX_REPORT_ECHO):=messageField(nodeE,nodeA,2,KEX_REP)
									messageField(nodeA,nodeE,3,EC_KEX_REPORT_ECHO):=messageField(nodeE,nodeA,3,KEX_REP)
									messageField(nodeA,nodeE,4,EC_KEX_REPORT_ECHO):=messageField(nodeE,nodeA,4,KEX_REP)
									messageField(nodeA,nodeE,5,EC_KEX_REPORT_ECHO):=messageField(nodeE,nodeA,5,KEX_REP)
									messageField(nodeA,nodeE,6,EC_KEX_REPORT_ECHO):=messageField(nodeE,nodeA,6,KEX_REP)
									messageField(nodeA,nodeE,7,EC_KEX_REPORT_ECHO):=messageField(nodeE,nodeA,7,KEX_REP)
								endpar
							else
								par
									controllerState(self) := ERROR_C
									protocolMessage( self , $eslv ) := KEX_FAIL_AUTH
								endpar											
							endif
						else
							par
								controllerState(self) := ERROR_C
								protocolMessage( self , $eslv ) := KEX_FAIL_DECRYPT
							endpar
						endif
					endpar	
				endif	
			endif
		endlet	
	
	rule r_evalkexReportEcho =	
		let ($ectrl=nodeE) in
			if(slaveState(self) = WAIT_KEX_REPORT_ECHO and protocolMessage( $ectrl ,self ) = EC_KEX_REPORT_ECHO)then
				if(not(passed(TBI1)))then 
					par				
						if(symDec(EC_KEX_REPORT_ECHO,1,1,7,self)=true and symEnc(EC_KEX_REPORT_ECHO,1,1,7)!=KT_ERROR)then
							if(messageField(nodeB,nodeE,1,KEX_REP)=messageField(nodeE,nodeB,1,EC_KEX_REPORT_ECHO) and messageField(nodeB,nodeE,2,KEX_REP)=messageField(nodeE,nodeB,2,EC_KEX_REPORT_ECHO) 
								and messageField(nodeB,nodeE,3,KEX_REP)=messageField(nodeE,nodeB,3,EC_KEX_REPORT_ECHO) and messageField(nodeB,nodeE,4,KEX_REP)=messageField(nodeE,nodeB,4,EC_KEX_REPORT_ECHO)
								and messageField(nodeB,nodeE,5,KEX_REP)=messageField(nodeE,nodeB,5,EC_KEX_REPORT_ECHO) and messageField(nodeB,nodeE,6,KEX_REP)=messageField(nodeE,nodeB,6,EC_KEX_REPORT_ECHO)
								and messageField(nodeB,nodeE,7,KEX_REP)=messageField(nodeE,nodeB,7,EC_KEX_REPORT_ECHO))then
								slaveState(self) := OK_S
							else
								par
									slaveState(self) := ERROR_S
									protocolMessage( self , $ectrl ) := KEX_FAIL_AUTH
								endpar
							endif
						else
							par
								slaveState(self) := ERROR_S
								protocolMessage( self , $ectrl ) := KEX_FAIL_DECRYPT
							endpar
						endif
						startTimer(TBI1) := false
					endpar	
				endif
			endif
		endlet	
		
	rule r_kexReportEchoReplay=
		let ($slv=nodeB,$ctrl=nodeA)in
			if(protocolMessage( $ctrl ,self ) = EC_KEX_REPORT_ECHO and protocolMessage($slv ,self) = EC_SEI_KEX_SET_ECHO and protocolMessage( self , $slv ) != EC_KEX_REPORT_ECHO)then
				par
					protocolMessage( self , $slv ) := EC_KEX_REPORT_ECHO
					messageField(nodeE,nodeB,1,EC_KEX_REPORT_ECHO):=messageField(nodeA,nodeE,1,EC_KEX_REPORT_ECHO)
					messageField(nodeE,nodeB,2,EC_KEX_REPORT_ECHO):=messageField(nodeA,nodeE,2,EC_KEX_REPORT_ECHO)
					messageField(nodeE,nodeB,3,EC_KEX_REPORT_ECHO):=messageField(nodeA,nodeE,3,EC_KEX_REPORT_ECHO)
					messageField(nodeE,nodeB,4,EC_KEX_REPORT_ECHO):=messageField(nodeA,nodeE,4,EC_KEX_REPORT_ECHO)
					messageField(nodeE,nodeB,5,EC_KEX_REPORT_ECHO):=messageField(nodeA,nodeE,5,EC_KEX_REPORT_ECHO)
					messageField(nodeE,nodeB,6,EC_KEX_REPORT_ECHO):=messageField(nodeA,nodeE,6,EC_KEX_REPORT_ECHO)
					messageField(nodeE,nodeB,7,EC_KEX_REPORT_ECHO):=messageField(nodeA,nodeE,7,EC_KEX_REPORT_ECHO)
				endpar	
			endif
		endlet
			
	rule r_kexReportEchoCraft=
		let ($slv=nodeB)in
			if(protocolMessage( $slv ,self ) = EC_SEI_KEX_SET_ECHO and knowsSymKey(self,KT2)=true and protocolMessage( self , $slv ) != EC_KEX_REPORT_ECHO)then
				par
					protocolMessage( self , $slv ) := EC_KEX_REPORT_ECHO
					symEnc(EC_KEX_REPORT_ECHO,1,1,7):=KT2
					messageField(nodeE,nodeB,1,EC_KEX_REPORT_ECHO):=messageField(nodeB,nodeE,1,KEX_REP)
					messageField(nodeE,nodeB,2,EC_KEX_REPORT_ECHO):=messageField(nodeB,nodeE,2,KEX_REP)
					messageField(nodeE,nodeB,3,EC_KEX_REPORT_ECHO):=messageField(nodeB,nodeE,3,KEX_REP)
					messageField(nodeE,nodeB,4,EC_KEX_REPORT_ECHO):=messageField(nodeB,nodeE,4,KEX_REP)
					messageField(nodeE,nodeB,5,EC_KEX_REPORT_ECHO):=messageField(nodeB,nodeE,5,KEX_REP)
					messageField(nodeE,nodeB,6,EC_KEX_REPORT_ECHO):=messageField(nodeB,nodeE,6,KEX_REP)
					messageField(nodeE,nodeB,7,EC_KEX_REPORT_ECHO):=messageField(nodeB,nodeE,7,KEX_REP)
				endpar
			endif
		endlet		

	rule r_failCatchSlave =
		let ($ectrl=nodeE, $slv=nodeB)in
			if((protocolMessage( $ectrl ,self ) = KEX_FAIL_KEX_KEY or protocolMessage( $ectrl ,self ) = KEX_FAIL_KEX_SCHEME or protocolMessage( $ectrl ,self ) = KEX_FAIL_KEX_CURVE or protocolMessage( $ectrl ,self ) = KEX_FAIL_CANCEL or protocolMessage( $ectrl ,self ) = KEX_FAIL_AUTH or protocolMessage( $ectrl ,self ) = KEX_FAIL_DECRYPT) and slaveState(self) != TIMEOUT_S )then
				slaveState($slv) := ERROR_S
			endif
		endlet
		
	rule r_failCatchCtrl =
		let($eslv=nodeE,$ctrl=nodeA)in
			if((protocolMessage( $eslv ,self ) = KEX_FAIL_KEX_KEY or protocolMessage( $eslv ,self ) = KEX_FAIL_KEX_SCHEME or protocolMessage( $eslv ,self ) = KEX_FAIL_KEX_CURVE or protocolMessage( $eslv ,self ) = KEX_FAIL_CANCEL or protocolMessage( $eslv ,self ) = KEX_FAIL_AUTH or protocolMessage( $eslv ,self ) = KEX_FAIL_DECRYPT) and controllerState(self) != TIMEOUT_C)then
				controllerState($ctrl) := ERROR_C
			endif
			endlet

	rule r_controllerRule =
		
		par
			r_initEnvCtrl[]
			r_kexGet[]
			r_timeoutTa1[]
			r_timeoutTia1[]
			r_evalKexReport[]
			r_timeoutTa2[]
			r_kexSet[]
			r_timeoutTia2[]
			r_insertPin[]
			r_nonceReport[]
			r_evalkexSetEcho[]
			r_failCatchCtrl[]
		endpar
	
	
	rule r_slaveRule =
	
		par
			r_initEnvSlv[]
			r_timeoutTb1[]
			r_kexReport[]
			r_timeoutTb2[]
			r_evalKexSet[]
			r_timeoutTb3[]
			r_sendSlvPubKey[]
			r_timeoutTib1[] 
			r_insertPinCsa[]
			r_SPANestablishment[]
			r_evalkexReportEcho[]
			r_failCatchSlave[]
						
		endpar
		

	rule r_mitmRule =
	
		if(mode=ACTIVE)then
			par
				r_kexReportCraft[]
				//r_saveKexSet[]
				r_sendEslvKey[]
				r_nonceGetCraft[]
				r_SPANCraft[]
				r_kexGetReplay[]
				r_kexSetCraft[] //save received report and send kex set without change anything
				r_sendEctrlKey[]
				r_nonceReportCraft[]
				r_bruteForce[]
				r_kexReportEchoCraft[]
							
			endpar
		else
			par
				r_kexGetReplay[]
				r_kexReportReplay[]
				r_kexSetReplay[]
				r_sendSlvPubKeyReplay[]
				r_sendCtrlPubKeyReplay[]
				r_nonceGetReplay[]
				r_nonceReportReplay[]
				r_SPANReplay[]
				r_kexReportEchoReplay[]
							
			endpar
		endif
		
		
main rule r_Main =
		par
			program(nodeA)
			program(nodeE)
			program(nodeB)		
		endpar	
		
default init s0:
	function slaveState($s in Receiver) = if($s = nodeB )then INIT_SLV endif
	function controllerState($c in Initiator) = if($c = nodeA )then INIT_CTRL endif
	function startTimer($s in Time)= false
	function messageArrived = false
	function cracked=false
	function knowsAsymPubKey($s in Agent, $ks in KnowledgeAsymPubKey)=if(($s = nodeB and $ks=KPUB_SLV or $ks=OB_KEY_SLV) or ($s = nodeA and $ks=KPUB_CTRL or $ks=OB_KEY_CTRL ) or ($s = nodeE and $ks=OB_KEY_MITM_CTRL or $ks=OB_KEY_MITM_SLV or $ks=KPUB_MITM_SLV or $ks=KPUB_MITM_CTRL)) then true else false endif
	
	function knowsAsymPrivKey($s in Agent, $ks in KnowledgeAsymPrivKey)=if(($s = nodeB and $ks=KPRIV_SLV) or ($s = nodeA and $ks=KPRIV_CTRL) or ($s = nodeE and $ks=KPRIV_MITM_CTRL or $ks=KPRIV_MITM_SLV)) then true else false endif
	function knowsSymKey($s in Agent, $ks in KnowledgeSymKey)=false

	function  protocolMessage($s in Agent, $r in Agent)= EMPTY
	function mode=chosenMode
	function qrKey=
			switch chosenQrCode
				case OB_KEY_CTRL: KPUB_CTRL
				case OB_KEY_MITM_CTRL: KPUB_MITM_CTRL
				case OB_KEY_MITM_SLV: KPUB_MITM_SLV
				case OB_KEY_SLV: KPUB_SLV
				case KPUB_MITM_SLV : KPUB_MITM_SLV
				case KPUB_CTRL: KPUB_CTRL
				case KPUB_MITM_CTRL: KPUB_MITM_CTRL
				case KPUB_SLV: KPUB_SLV
			endswitch
	function qrCodeUseDecison=chosenQrCodeUsage
	
	agent Initiator:		
			r_controllerRule[]
			
	agent Intruder:		
			r_mitmRule[]
				
	agent Receiver:
			r_slaveRule[]
			
			
