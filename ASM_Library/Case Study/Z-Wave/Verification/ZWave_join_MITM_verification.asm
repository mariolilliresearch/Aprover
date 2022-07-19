asm ZWave_join_MITM_verification

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
						   
						  
	//Attacker Mode
	enum domain Modality = {ACTIVE | PASSIVE} 
	
	//Knowledge
	//CSA | SKEX | ECDH | ACCESS_S2 | AUTH_S2| UNAUTH_S2 | SO | 	
	enum domain KnowledgeBitString = {PIN_OK | PIN_ERROR}
	enum domain	KnowledgeBitStringCSA= {CSA_0 | CSA_1}
	enum domain	KnowledgeBitStringSKEX= {SKEX_0 | SKEX_1}
	enum domain	KnowledgeBitStringECDH = {ECDH_0 | ECDH_1}
	enum domain	KnowledgeBitStringACCESS_S2= {ACCESS_S2_0 | ACCESS_S2_1}
	enum domain	KnowledgeBitStringAUTH_S2= {AUTH_S2_0 | AUTH_S2_1}
	enum domain	KnowledgeBitStringUNAUTH_S2= {UNAUTH_S2_0 | UNAUTH_S2_1}
	enum domain	KnowledgeBitStringSO= {SO_0 | SO_1}
	enum domain KnowledgeSymKey = {KT1 | KT2 | KT3 | KT_ERROR}
	enum domain KnowledgeAsymPrivKey = {KPRIV_CTRL | KPRIV_SLV | KPRIV_MITM_CTRL | KPRIV_MITM_SLV }
	enum domain KnowledgeAsymPubKey = {KPUB_SLV | KPUB_CTRL | KPUB_MITM_CTRL | KPUB_MITM_SLV | KPUB_ERR | OB_KEY_MITM_CTRL | OB_KEY_MITM_SLV | OB_KEY_SLV | OB_KEY_CTRL}
	
	
	
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
	
	controlled protocolMessage: Prod(Initiator,Intruder)-> Message
	controlled protocolMessage: Prod(Intruder,Initiator)-> Message
	controlled protocolMessage: Prod(Receiver,Intruder)-> Message
	controlled protocolMessage: Prod(Intruder,Receiver)-> Message
	
	monitored chosenMode: Modality
	controlled mode: Modality
	
	//controlled messageField: Prod(FieldPosition,Message)->Knowledge
	
	controlled messageField_nodeB_nodeE_1_KEX_REP:KnowledgeBitStringCSA
	controlled messageField_nodeE_nodeA_1_KEX_REP:KnowledgeBitStringCSA
	controlled messageField_nodeB_nodeE_2_KEX_REP:KnowledgeBitStringSKEX
	controlled messageField_nodeE_nodeA_2_KEX_REP:KnowledgeBitStringSKEX
	controlled messageField_nodeB_nodeE_3_KEX_REP:KnowledgeBitStringECDH
	controlled messageField_nodeE_nodeA_3_KEX_REP:KnowledgeBitStringECDH
	controlled messageField_nodeB_nodeE_4_KEX_REP:KnowledgeBitStringACCESS_S2
	controlled messageField_nodeE_nodeA_4_KEX_REP:KnowledgeBitStringACCESS_S2
	controlled messageField_nodeB_nodeE_5_KEX_REP:KnowledgeBitStringAUTH_S2
	controlled messageField_nodeE_nodeA_5_KEX_REP:KnowledgeBitStringAUTH_S2
	controlled messageField_nodeB_nodeE_6_KEX_REP:KnowledgeBitStringUNAUTH_S2
	controlled messageField_nodeE_nodeA_6_KEX_REP:KnowledgeBitStringUNAUTH_S2
	controlled messageField_nodeB_nodeE_7_KEX_REP:KnowledgeBitStringSO
	controlled messageField_nodeE_nodeA_7_KEX_REP:KnowledgeBitStringSO
	
	controlled messageField_nodeA_nodeE_1_KEX_SET:KnowledgeBitStringCSA
	controlled messageField_nodeE_nodeB_1_KEX_SET:KnowledgeBitStringCSA
	controlled messageField_nodeA_nodeE_2_KEX_SET:KnowledgeBitStringSKEX
	controlled messageField_nodeE_nodeB_2_KEX_SET:KnowledgeBitStringSKEX
	controlled messageField_nodeA_nodeE_3_KEX_SET:KnowledgeBitStringECDH
	controlled messageField_nodeE_nodeB_3_KEX_SET:KnowledgeBitStringECDH
	controlled messageField_nodeA_nodeE_4_KEX_SET:KnowledgeBitStringACCESS_S2
	controlled messageField_nodeE_nodeB_4_KEX_SET:KnowledgeBitStringACCESS_S2
	controlled messageField_nodeA_nodeE_5_KEX_SET:KnowledgeBitStringAUTH_S2
	controlled messageField_nodeE_nodeB_5_KEX_SET:KnowledgeBitStringAUTH_S2
	controlled messageField_nodeA_nodeE_6_KEX_SET:KnowledgeBitStringUNAUTH_S2
	controlled messageField_nodeE_nodeB_6_KEX_SET:KnowledgeBitStringUNAUTH_S2
	controlled messageField_nodeA_nodeE_7_KEX_SET:KnowledgeBitStringSO
	controlled messageField_nodeE_nodeB_7_KEX_SET:KnowledgeBitStringSO
	
	controlled messageField_nodeB_nodeE_1_PUB_KEY_REP_JOIN:KnowledgeAsymPubKey
	controlled messageField_nodeE_nodeA_1_PUB_KEY_REP_JOIN:KnowledgeAsymPubKey
	controlled messageField_nodeA_nodeE_1_PUB_KEY_REP_CTRL:KnowledgeAsymPubKey
	controlled messageField_nodeE_nodeB_1_PUB_KEY_REP_CTRL:KnowledgeAsymPubKey
	controlled messageField_nodeB_nodeE_1_PUB_KEY_REP_JOIN_OB:KnowledgeAsymPubKey
	controlled messageField_nodeE_nodeA_1_PUB_KEY_REP_JOIN_OB:KnowledgeAsymPubKey
	controlled messageField_nodeA_nodeE_1_PUB_KEY_REP_CTRL_OB:KnowledgeAsymPubKey
	controlled messageField_nodeE_nodeB_1_PUB_KEY_REP_CTRL_OB:KnowledgeAsymPubKey
	
	controlled messageField_nodeB_nodeE_1_EC_SEI_KEX_SET_ECHO:KnowledgeBitStringCSA
	controlled messageField_nodeE_nodeA_1_EC_SEI_KEX_SET_ECHO:KnowledgeBitStringCSA
	controlled messageField_nodeB_nodeE_2_EC_SEI_KEX_SET_ECHO:KnowledgeBitStringSKEX
	controlled messageField_nodeE_nodeA_2_EC_SEI_KEX_SET_ECHO:KnowledgeBitStringSKEX
	controlled messageField_nodeB_nodeE_3_EC_SEI_KEX_SET_ECHO:KnowledgeBitStringECDH
	controlled messageField_nodeE_nodeA_3_EC_SEI_KEX_SET_ECHO:KnowledgeBitStringECDH
	controlled messageField_nodeB_nodeE_4_EC_SEI_KEX_SET_ECHO:KnowledgeBitStringACCESS_S2
	controlled messageField_nodeE_nodeA_4_EC_SEI_KEX_SET_ECHO:KnowledgeBitStringACCESS_S2
	controlled messageField_nodeB_nodeE_5_EC_SEI_KEX_SET_ECHO:KnowledgeBitStringAUTH_S2
	controlled messageField_nodeE_nodeA_5_EC_SEI_KEX_SET_ECHO:KnowledgeBitStringAUTH_S2
	controlled messageField_nodeB_nodeE_6_EC_SEI_KEX_SET_ECHO:KnowledgeBitStringUNAUTH_S2
	controlled messageField_nodeE_nodeA_6_EC_SEI_KEX_SET_ECHO:KnowledgeBitStringUNAUTH_S2
	controlled messageField_nodeB_nodeE_7_EC_SEI_KEX_SET_ECHO:KnowledgeBitStringSO
	controlled messageField_nodeE_nodeA_7_EC_SEI_KEX_SET_ECHO:KnowledgeBitStringSO
	
	controlled messageField_nodeA_nodeE_1_EC_KEX_REPORT_ECHO:KnowledgeBitStringCSA
	controlled messageField_nodeE_nodeB_1_EC_KEX_REPORT_ECHO:KnowledgeBitStringCSA
	controlled messageField_nodeA_nodeE_2_EC_KEX_REPORT_ECHO:KnowledgeBitStringSKEX
	controlled messageField_nodeE_nodeB_2_EC_KEX_REPORT_ECHO:KnowledgeBitStringSKEX
	controlled messageField_nodeA_nodeE_3_EC_KEX_REPORT_ECHO:KnowledgeBitStringECDH
	controlled messageField_nodeE_nodeB_3_EC_KEX_REPORT_ECHO:KnowledgeBitStringECDH
	controlled messageField_nodeA_nodeE_4_EC_KEX_REPORT_ECHO:KnowledgeBitStringACCESS_S2
	controlled messageField_nodeE_nodeB_4_EC_KEX_REPORT_ECHO:KnowledgeBitStringACCESS_S2
	controlled messageField_nodeA_nodeE_5_EC_KEX_REPORT_ECHO:KnowledgeBitStringAUTH_S2
	controlled messageField_nodeE_nodeB_5_EC_KEX_REPORT_ECHO:KnowledgeBitStringAUTH_S2
	controlled messageField_nodeA_nodeE_6_EC_KEX_REPORT_ECHO:KnowledgeBitStringUNAUTH_S2
	controlled messageField_nodeE_nodeB_6_EC_KEX_REPORT_ECHO:KnowledgeBitStringUNAUTH_S2
	controlled messageField_nodeA_nodeE_7_EC_KEX_REPORT_ECHO:KnowledgeBitStringSO
	controlled messageField_nodeE_nodeB_7_EC_KEX_REPORT_ECHO:KnowledgeBitStringSO
	                                              

	controlled symEnc: Prod(Message,Level,EncField1,EncField2)-> KnowledgeSymKey
	static symDec: Prod(Message,Level,EncField1,EncField2,Intruder)-> Boolean
	static symDec: Prod(Message,Level,EncField1,EncField2,Receiver)-> Boolean
	static symDec: Prod(Message,Level,EncField1,EncField2,Initiator)-> Boolean
	
	static diffieHellman:Prod(KnowledgeAsymPubKey,KnowledgeAsymPrivKey)->KnowledgeSymKey
	/*------------------------------------------------------------------- */
	//            Knowledge  management of the principals 
	/*------------------------------------------------------------------- */
	controlled knowsBitString:Prod(Initiator,KnowledgeBitString)->Boolean
	controlled knowsBitString:Prod(Receiver,KnowledgeBitString)->Boolean
	controlled knowsBitString:Prod(Intruder,KnowledgeBitString)->Boolean
	
	controlled knowsBitStringCSA:Prod(Initiator,KnowledgeBitStringCSA)->Boolean
	controlled knowsBitStringCSA:Prod(Receiver,KnowledgeBitStringCSA)->Boolean
	controlled knowsBitStringCSA:Prod(Intruder,KnowledgeBitStringCSA)->Boolean
	
	
	controlled knowsBitStringSKEX:Prod(Initiator,KnowledgeBitStringSKEX)->Boolean
	controlled knowsBitStringSKEX:Prod(Receiver,KnowledgeBitStringSKEX)->Boolean
	controlled knowsBitStringSKEX:Prod(Intruder,KnowledgeBitStringSKEX)->Boolean
	
	controlled knowsBitStringECDH:Prod(Initiator,KnowledgeBitStringECDH)->Boolean
	controlled knowsBitStringECDH:Prod(Receiver,KnowledgeBitStringECDH)->Boolean
	controlled knowsBitStringECDH:Prod(Intruder,KnowledgeBitStringECDH)->Boolean
	
	controlled knowsBitStringACCESS_S2:Prod(Initiator,KnowledgeBitStringACCESS_S2)->Boolean
	controlled knowsBitStringACCESS_S2:Prod(Receiver,KnowledgeBitStringACCESS_S2)->Boolean
	controlled knowsBitStringACCESS_S2:Prod(Intruder,KnowledgeBitStringACCESS_S2)->Boolean
	
	controlled knowsBitStringAUTH_S2:Prod(Initiator,KnowledgeBitStringAUTH_S2)->Boolean
	controlled knowsBitStringAUTH_S2:Prod(Receiver,KnowledgeBitStringAUTH_S2)->Boolean
	controlled knowsBitStringAUTH_S2:Prod(Intruder,KnowledgeBitStringAUTH_S2)->Boolean
	
	controlled knowsBitStringUNAUTH_S2:Prod(Initiator,KnowledgeBitStringUNAUTH_S2)->Boolean
	controlled knowsBitStringUNAUTH_S2:Prod(Receiver,KnowledgeBitStringUNAUTH_S2)->Boolean
	controlled knowsBitStringUNAUTH_S2:Prod(Intruder,KnowledgeBitStringUNAUTH_S2)->Boolean
	
	controlled knowsBitStringSO:Prod(Initiator,KnowledgeBitStringSO)->Boolean
	controlled knowsBitStringSO:Prod(Receiver,KnowledgeBitStringSO)->Boolean
	controlled knowsBitStringSO:Prod(Intruder,KnowledgeBitStringSO)->Boolean
	
	
	controlled knowsSymKey:Prod(Initiator,KnowledgeSymKey)->Boolean
	controlled knowsSymKey:Prod(Receiver,KnowledgeSymKey)->Boolean
	controlled knowsSymKey:Prod(Intruder,KnowledgeSymKey)->Boolean
	
	controlled knowsAsymPubKey:Prod(Initiator,KnowledgeAsymPubKey)->Boolean
	controlled knowsAsymPubKey:Prod(Receiver,KnowledgeAsymPubKey)->Boolean
	controlled knowsAsymPubKey:Prod(Intruder,KnowledgeAsymPubKey)->Boolean
	
	controlled knowsAsymPrivKey:Prod(Initiator,KnowledgeAsymPrivKey)->Boolean
	controlled knowsAsymPrivKey:Prod(Receiver,KnowledgeAsymPrivKey)->Boolean
	controlled knowsAsymPrivKey:Prod(Intruder,KnowledgeAsymPrivKey)->Boolean
	
	
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
	
	function symDec($m in Message,$l in Level,$f1 in EncField1,$f2 in EncField2,$d in Initiator)=
		if(knowsSymKey($d,symEnc($m,$l,$f1,$f2))=true)then
			true
		else
			false
		endif
		
	function symDec($m in Message,$l in Level,$f1 in EncField1,$f2 in EncField2,$d in Receiver)=
		if(knowsSymKey($d,symEnc($m,$l,$f1,$f2))=true)then
			true
		else
			false
		endif
	
	function symDec($m in Message,$l in Level,$f1 in EncField1,$f2 in EncField2,$d in Intruder)=
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
						knowsBitStringCSA(self,CSA_1):= true
						knowsBitStringCSA(self,CSA_0):= false
						knowsBitStringSKEX(self,SKEX_0):=false
						knowsBitStringSKEX(self,SKEX_1):= true
						knowsBitStringECDH(self,ECDH_0):= false	
						knowsBitStringECDH(self,ECDH_1):= true
						knowsBitStringACCESS_S2(self,ACCESS_S2_0):= false
						knowsBitStringACCESS_S2(self,ACCESS_S2_1):= true
						knowsBitStringAUTH_S2(self,AUTH_S2_0):=false
						knowsBitStringAUTH_S2(self,AUTH_S2_1):= true
						knowsBitStringUNAUTH_S2(self,UNAUTH_S2_0):= false
						knowsBitStringUNAUTH_S2(self,UNAUTH_S2_1):= true
						knowsBitStringSO(self,SO_0):= false
						knowsBitStringSO(self,SO_1):= true
										
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
						knowsBitStringSKEX(self,SKEX_1):=supportedSkex($type)
						knowsBitStringECDH(self,ECDH_1):=supportedEcdh($type)	
						knowsBitStringCSA(self,CSA_1):=supportedCsa($type)
						knowsBitStringACCESS_S2(self,ACCESS_S2_1):=supportedS2Access($type)
						knowsBitStringAUTH_S2(self,AUTH_S2_1):=supportedS2Auth($type)
						knowsBitStringUNAUTH_S2(self,UNAUTH_S2_1):=supportedS2Unauth($type)
						knowsBitStringSKEX(self,SKEX_0):=unSupportedSkex($type)
						knowsBitStringECDH(self,ECDH_0):=unSupportedEcdh($type)	
						knowsBitStringCSA(self,CSA_0):=unSupportedCsa($type)
						knowsBitStringACCESS_S2(self,ACCESS_S2_0):=unSupportedS2Access($type)
						knowsBitStringAUTH_S2(self,AUTH_S2_0):=unSupportedS2Auth($type)
						knowsBitStringUNAUTH_S2(self,UNAUTH_S2_0):=unSupportedS2Unauth($type)
						
					endpar
				endlet
				knowsBitStringSO(self,SO_1):= true
				knowsBitStringSO(self,SO_0):= false
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
						if(knowsBitStringCSA(self,CSA_1))then
							
								messageField_nodeB_nodeE_1_KEX_REP:= CSA_1
								
						else
							
								messageField_nodeB_nodeE_1_KEX_REP:= CSA_0
								
						endif
						if(knowsBitStringSKEX(self,SKEX_1))then
							
								messageField_nodeB_nodeE_2_KEX_REP:= SKEX_1
								
						else
							
								messageField_nodeB_nodeE_2_KEX_REP:= SKEX_0
								
						endif
						if(knowsBitStringECDH(self,ECDH_1))then
							
								messageField_nodeB_nodeE_3_KEX_REP:= ECDH_1
								
						else
							
								messageField_nodeB_nodeE_3_KEX_REP:= ECDH_0
								
						endif
						if(knowsBitStringACCESS_S2(self,ACCESS_S2_1))then
							
								messageField_nodeB_nodeE_4_KEX_REP:= ACCESS_S2_1
								
						else
							
								messageField_nodeB_nodeE_4_KEX_REP:= ACCESS_S2_0
								
						endif
						if(knowsBitStringAUTH_S2(self,AUTH_S2_1))then
							
								messageField_nodeB_nodeE_5_KEX_REP:= AUTH_S2_1
								
						else
							
								messageField_nodeB_nodeE_5_KEX_REP:= AUTH_S2_0
								
						endif
						if(knowsBitStringUNAUTH_S2(self,UNAUTH_S2_1))then
							
								messageField_nodeB_nodeE_6_KEX_REP:= UNAUTH_S2_1
								
						else
						
								messageField_nodeB_nodeE_6_KEX_REP:= UNAUTH_S2_0
								
						endif
						
						messageField_nodeB_nodeE_7_KEX_REP:= SO_1
						
						
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
					messageField_nodeE_nodeB_1_KEX_SET:= messageField_nodeB_nodeE_1_KEX_REP
					messageField_nodeE_nodeB_2_KEX_SET:= messageField_nodeB_nodeE_2_KEX_REP	
					messageField_nodeE_nodeB_3_KEX_SET:= messageField_nodeB_nodeE_3_KEX_REP
					messageField_nodeE_nodeB_4_KEX_SET:= messageField_nodeB_nodeE_4_KEX_REP
					messageField_nodeE_nodeB_5_KEX_SET:= messageField_nodeB_nodeE_5_KEX_REP	
					messageField_nodeE_nodeB_6_KEX_SET:= messageField_nodeB_nodeE_6_KEX_REP
					messageField_nodeE_nodeB_7_KEX_SET:= messageField_nodeB_nodeE_7_KEX_REP	
					
					
				
				endpar
			endif
		endlet
		
	rule r_kexReportReplay =
		let ($ctrl=nodeA, $slv=nodeB) in
			if(protocolMessage(  $ctrl , self ) = KEX_GET  and protocolMessage(  $slv, self ) = KEX_REP  and protocolMessage( self,$ctrl ) != KEX_REP)then
					par
						protocolMessage(  self, $ctrl ) := KEX_REP
						// KEX REPORT payload
						messageField_nodeE_nodeA_1_KEX_REP:=messageField_nodeB_nodeE_1_KEX_REP
						messageField_nodeE_nodeA_2_KEX_REP:=messageField_nodeB_nodeE_2_KEX_REP
						messageField_nodeE_nodeA_3_KEX_REP:=messageField_nodeB_nodeE_3_KEX_REP
						messageField_nodeE_nodeA_4_KEX_REP:=messageField_nodeB_nodeE_4_KEX_REP
						messageField_nodeE_nodeA_5_KEX_REP:=messageField_nodeB_nodeE_5_KEX_REP
						messageField_nodeE_nodeA_6_KEX_REP:=messageField_nodeB_nodeE_6_KEX_REP
						messageField_nodeE_nodeA_7_KEX_REP:=messageField_nodeB_nodeE_7_KEX_REP
						
					endpar
			endif
		endlet
	
		rule r_kexSetReplay =
		let ($slv=nodeB, $ctrl=nodeA) in
			if(protocolMessage($ctrl , self) = KEX_SET and protocolMessage(self , $slv) = KEX_GET)then
				par		
					
					protocolMessage(  self, $slv ) := KEX_SET			
					// KEX SET payload, auto approves all_requested key					
					messageField_nodeE_nodeB_1_KEX_SET:=messageField_nodeA_nodeE_1_KEX_SET
					messageField_nodeE_nodeB_2_KEX_SET:=messageField_nodeA_nodeE_2_KEX_SET
					messageField_nodeE_nodeB_3_KEX_SET:=messageField_nodeA_nodeE_3_KEX_SET
					messageField_nodeE_nodeB_4_KEX_SET:=messageField_nodeA_nodeE_4_KEX_SET
					messageField_nodeE_nodeB_5_KEX_SET:=messageField_nodeA_nodeE_5_KEX_SET
					messageField_nodeE_nodeB_6_KEX_SET:=messageField_nodeA_nodeE_6_KEX_SET
					messageField_nodeE_nodeB_7_KEX_SET:=messageField_nodeA_nodeE_7_KEX_SET
					
					
				
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
						messageField_nodeE_nodeA_1_KEX_REP:=messageField_nodeB_nodeE_1_KEX_REP
						messageField_nodeE_nodeA_2_KEX_REP:=messageField_nodeB_nodeE_2_KEX_REP
						messageField_nodeE_nodeA_3_KEX_REP:=messageField_nodeB_nodeE_3_KEX_REP
						messageField_nodeE_nodeA_4_KEX_REP:=messageField_nodeB_nodeE_4_KEX_REP
						messageField_nodeE_nodeA_5_KEX_REP:=messageField_nodeB_nodeE_5_KEX_REP
						messageField_nodeE_nodeA_6_KEX_REP:=messageField_nodeB_nodeE_6_KEX_REP
						messageField_nodeE_nodeA_7_KEX_REP:=messageField_nodeB_nodeE_7_KEX_REP
						
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
	     	 	and (knowsBitStringACCESS_S2(self,messageField_nodeE_nodeA_4_KEX_REP)=true or knowsBitStringAUTH_S2(self,messageField_nodeE_nodeA_5_KEX_REP)=true
	 	 		or knowsBitStringUNAUTH_S2(self,messageField_nodeE_nodeA_6_KEX_REP)=true or knowsBitStringSO(self,messageField_nodeE_nodeA_7_KEX_REP)=true)) then
	 	 		if(not(passed(TAI1)))then
		 	 		
						controllerState(self) := WAIT_EVAL_KEX_SCHEME				
						
				endif
	     	 endif
		endlet
		
		rule r_failEvalReqKey=
     	 let ($eslv=nodeE) in
	     	 if(controllerState(self) = WAIT_EVAL_KEX_KEY  and protocolMessage($eslv,self) = KEX_REP 
	     	 	and not (knowsBitStringACCESS_S2(self,messageField_nodeE_nodeA_4_KEX_REP)=true or knowsBitStringAUTH_S2(self,messageField_nodeE_nodeA_5_KEX_REP)=true
	 	 		or knowsBitStringUNAUTH_S2(self,messageField_nodeE_nodeA_6_KEX_REP)=true or knowsBitStringSO(self,messageField_nodeE_nodeA_7_KEX_REP)=true)) then
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
     	 	if(controllerState(self) = WAIT_EVAL_KEX_SCHEME and protocolMessage(  $eslv , self ) = KEX_REP and messageField_nodeE_nodeA_2_KEX_REP=SKEX_1 ) then
				if(not(passed(TAI1)))then
					
						controllerState(self) := WAIT_EVAL_KEX_CURVE
						
				endif
			endif
		endlet
    
	rule r_failEvalReqScheme=
     	 let ($eslv=nodeE) in 
     	 	if(controllerState(self) = WAIT_EVAL_KEX_SCHEME and protocolMessage($eslv , self) = KEX_REP and messageField_nodeE_nodeA_2_KEX_REP=SKEX_0 ) then
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
     	 	if(controllerState(self) = WAIT_EVAL_KEX_CURVE and protocolMessage($eslv , self) = KEX_REP and messageField_nodeE_nodeA_3_KEX_REP=ECDH_1 ) then
				if(not(passed(TAI1)))then
					
						controllerState(self) := WAIT_EVAL_CSA
						
				endif
			endif
		endlet
      
	rule r_failEvalReqCurve=
     	 let ($eslv=nodeE) in 
     	 	if(controllerState(self) = WAIT_EVAL_KEX_CURVE and protocolMessage($eslv , self) = KEX_REP and messageField_nodeE_nodeA_3_KEX_REP=ECDH_0 ) then
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
     	 	if(controllerState(self) = WAIT_EVAL_CSA and protocolMessage($eslv,self) = KEX_REP  and messageField_nodeE_nodeA_1_KEX_REP=CSA_0) then
				if(not(passed(TAI1)))then
				
						controllerState(self) := WAIT_ECDH_PUB_JOIN						
				
				endif
			endif
		endlet 
	 	
	rule r_failEvalReqCsa=
		let ($eslv=nodeE) in 
     	 	if(controllerState(self) = WAIT_EVAL_CSA and protocolMessage($eslv,self) = KEX_REP  and messageField_nodeE_nodeA_1_KEX_REP=CSA_1) then
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
						                                                     
						messageField_nodeA_nodeE_1_KEX_SET:=messageField_nodeE_nodeA_1_KEX_REP
						messageField_nodeA_nodeE_2_KEX_SET:=messageField_nodeE_nodeA_2_KEX_REP
						messageField_nodeA_nodeE_3_KEX_SET:=messageField_nodeE_nodeA_3_KEX_REP
						
						
						if(messageField_nodeE_nodeA_4_KEX_REP=ACCESS_S2_1 and userGrantS2Access)then
							
								messageField_nodeA_nodeE_4_KEX_SET:=ACCESS_S2_1
								
						else		
							
								messageField_nodeA_nodeE_4_KEX_SET:=ACCESS_S2_0
								
						endif
						if(messageField_nodeE_nodeA_5_KEX_REP=AUTH_S2_1 and userGrantS2Auth)then
							
								messageField_nodeA_nodeE_5_KEX_SET:=AUTH_S2_1
								
						else		
							
								messageField_nodeA_nodeE_5_KEX_SET:=AUTH_S2_0
								
						endif
						if(messageField_nodeE_nodeA_6_KEX_REP=UNAUTH_S2_1 and userGrantS2Unauth)then
							
								messageField_nodeA_nodeE_6_KEX_SET:=UNAUTH_S2_1
								
						else		
							
								messageField_nodeA_nodeE_6_KEX_SET:=UNAUTH_S2_0
								
						endif
						if(messageField_nodeE_nodeA_7_KEX_REP=SO_1 and userGrantS0)then
							
								messageField_nodeA_nodeE_7_KEX_SET:=SO_1
								
						else		
							
								messageField_nodeA_nodeE_7_KEX_SET:=SO_0
								
						endif	
					endpar
				endif
			endif
		endlet
/*
	rule r_saveKexSet =
		let( $ctrl=nodeA)in
			if(protocolMessage( $ctrl , self ) = KEX_SET)then 
				par
					sessionKnowledge_nodeE_nodeA_1_KEX_SET:=messageField_nodeA_nodeE_1_KEX_SET
					sessionKnowledge_nodeE_nodeA_2_KEX_SET:=messageField_nodeA_nodeE_2_KEX_SET
					sessionKnowledge_nodeE_nodeA_3_KEX_SET:=messageField_nodeA_nodeE_3_KEX_SET
					sessionKnowledge_nodeE_nodeA_4_KEX_SET:=messageField_nodeA_nodeE_4_KEX_SET
					sessionKnowledge_nodeE_nodeA_5_KEX_SET:=messageField_nodeA_nodeE_5_KEX_SET
					sessionKnowledge_nodeE_nodeA_6_KEX_SET:=messageField_nodeA_nodeE_6_KEX_SET
					sessionKnowledge_nodeE_nodeA_7_KEX_SET:=messageField_nodeA_nodeE_7_KEX_SET
				endpar		
			endif
		endlet
*/		
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
				((messageField_nodeE_nodeB_4_KEX_SET = messageField_nodeB_nodeE_4_KEX_REP or (messageField_nodeB_nodeE_4_KEX_REP=ACCESS_S2_1 and messageField_nodeE_nodeB_4_KEX_SET=ACCESS_S2_0))
					and (messageField_nodeE_nodeB_5_KEX_SET = messageField_nodeB_nodeE_5_KEX_REP or (messageField_nodeB_nodeE_5_KEX_REP=AUTH_S2_1 and messageField_nodeE_nodeB_5_KEX_SET=AUTH_S2_0))
					and (messageField_nodeE_nodeB_6_KEX_SET = messageField_nodeB_nodeE_6_KEX_REP or (messageField_nodeB_nodeE_6_KEX_REP=UNAUTH_S2_1 and messageField_nodeE_nodeB_6_KEX_SET=UNAUTH_S2_0))
					and (messageField_nodeE_nodeB_7_KEX_SET = messageField_nodeB_nodeE_7_KEX_REP or (messageField_nodeB_nodeE_7_KEX_REP=SO_1 and messageField_nodeE_nodeB_7_KEX_SET=SO_0))))then
					
						slaveState(self) := WAIT_EVAL_SET_KEX_SCHEME
						
			endif
		endlet
	
	rule r_failEvalGrantKey=
		let ($ectrl=nodeE) in
			if(slaveState(self) = WAIT_EVAL_SET_KEX_KEY  and protocolMessage(  $ectrl , self ) = KEX_SET and
				not((messageField_nodeE_nodeB_4_KEX_SET = messageField_nodeB_nodeE_4_KEX_REP or (messageField_nodeB_nodeE_4_KEX_REP=ACCESS_S2_1 and messageField_nodeE_nodeB_4_KEX_SET=ACCESS_S2_0))
					and (messageField_nodeE_nodeB_5_KEX_SET = messageField_nodeB_nodeE_5_KEX_REP or (messageField_nodeB_nodeE_5_KEX_REP=AUTH_S2_1 and messageField_nodeE_nodeB_5_KEX_SET=AUTH_S2_0))
					and (messageField_nodeE_nodeB_6_KEX_SET = messageField_nodeB_nodeE_6_KEX_REP or (messageField_nodeB_nodeE_6_KEX_REP=UNAUTH_S2_1 and messageField_nodeE_nodeB_6_KEX_SET=UNAUTH_S2_0))
					and (messageField_nodeE_nodeB_7_KEX_SET = messageField_nodeB_nodeE_7_KEX_REP or (messageField_nodeB_nodeE_7_KEX_REP=SO_1 and messageField_nodeE_nodeB_7_KEX_SET=SO_0))))then
					par
						protocolMessage(  self , $ectrl ) := KEX_FAIL_KEX_KEY
						slaveState(self) := ERROR_S
					endpar
			endif
		endlet

	rule r_evalGrantScheme=
		let ($ectrl=nodeE) in
			if(slaveState(self) = WAIT_EVAL_SET_KEX_SCHEME and protocolMessage(  $ectrl , self ) = KEX_SET and messageField_nodeE_nodeB_2_KEX_SET=SKEX_1)then
				
					slaveState(self) := WAIT_EVAL_SET_KEX_CURVE
					
			endif	
		endlet	
				
	rule r_failEvalGrantScheme=
		let ($ectrl=nodeE) in
			if(slaveState(self) = WAIT_EVAL_SET_KEX_SCHEME  and protocolMessage(  $ectrl , self ) = KEX_SET and messageField_nodeE_nodeB_2_KEX_SET=SKEX_0)then
				par
					protocolMessage(  self , $ectrl ) := KEX_FAIL_KEX_SCHEME
					slaveState(self) := ERROR_S
				endpar
			endif	
		endlet	
		
	rule r_evalGrantCurve=
		let ($ectrl=nodeE) in
			if(slaveState(self) = WAIT_EVAL_SET_KEX_CURVE  and protocolMessage(  $ectrl , self ) = KEX_SET and messageField_nodeE_nodeB_3_KEX_SET=ECDH_1)then
				
					slaveState(self) := WAIT_EVAL_SET_CSA	
					
			
			endif	
		endlet
	
	rule r_failEvalGrantCurve=
		let ($ectrl=nodeE) in
			if(slaveState(self) = WAIT_EVAL_SET_KEX_CURVE  and protocolMessage(  $ectrl , self ) = KEX_SET and messageField_nodeE_nodeB_3_KEX_SET=ECDH_0)then
				par
					protocolMessage(  self , $ectrl ) := KEX_FAIL_KEX_CURVE
					slaveState(self) := ERROR_S
				endpar
			endif	
		endlet	
		
	rule r_evalGrantCsa=
		let ($ectrl=nodeE) in
			if(slaveState(self) = WAIT_EVAL_SET_CSA  and protocolMessage($ectrl,self) = KEX_SET and messageField_nodeE_nodeB_1_KEX_SET=messageField_nodeB_nodeE_1_KEX_REP)then
				
					slaveState(self) := WAIT_ECDH_PUB_CTRL		
					
			endif	
		endlet	
		
	rule r_failEvalGrantCsa=
		let ($ectrl=nodeE) in
			if(slaveState(self) = WAIT_EVAL_SET_CSA  and protocolMessage($ectrl,self) = KEX_SET and messageField_nodeE_nodeB_1_KEX_SET!=messageField_nodeB_nodeE_1_KEX_REP)then
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
					if(messageField_nodeE_nodeB_1_KEX_SET = CSA_1 )then												
						messageField_nodeB_nodeE_1_PUB_KEY_REP_JOIN := KPUB_SLV//readKnowledge(self,KPUB_SLV)	
					else 
						messageField_nodeB_nodeE_1_PUB_KEY_REP_JOIN_OB := OB_KEY_SLV//readKnowledge(self,OB_KEY_SLV)															
					endif
				endpar
			endif
		endlet
		
	rule r_sendEctrlKey =
		let ($slv=nodeB) in
			if(protocolMessage( $slv , self ) = PUB_KEY_REP_JOIN and messageField_nodeB_nodeE_1_PUB_KEY_REP_JOIN_OB = OB_KEY_SLV)then
				par					
					protocolMessage( self , $slv ) := PUB_KEY_REP_CTRL
					messageField_nodeE_nodeB_1_PUB_KEY_REP_CTRL := KPUB_MITM_CTRL//readKnowledge(self,KPUB_MITM_CTRL)
					
				endpar
			endif
		endlet
		
	rule r_sendEslvKey = 
		let ($ctrl=nodeA) in
			if(protocolMessage( $ctrl , self ) = KEX_SET and knowsBitString(self,PIN_OK)=true)then
				par
					protocolMessage( self, $ctrl ) := PUB_KEY_REP_JOIN
					messageField_nodeE_nodeA_1_PUB_KEY_REP_JOIN_OB := OB_KEY_MITM_SLV//readKnowledge(self,OB_KEY_MITM_SLV)						
				endpar
			endif
		endlet
		
	rule r_sendSlvPubKeyReplay = 
		let ($ctrl=nodeA, $slv=nodeB) in
			if(protocolMessage( $ctrl , self ) = KEX_SET and protocolMessage($slv , self) = PUB_KEY_REP_JOIN and protocolMessage( self , $ctrl ) != PUB_KEY_REP_JOIN)then
				par
					protocolMessage( self, $ctrl ) := PUB_KEY_REP_JOIN
					if(messageField_nodeA_nodeE_1_KEX_SET=CSA_0)then
						par
							knowsAsymPubKey(self,messageField_nodeE_nodeA_1_PUB_KEY_REP_JOIN_OB):=true
							messageField_nodeE_nodeA_1_PUB_KEY_REP_JOIN_OB:=messageField_nodeB_nodeE_1_PUB_KEY_REP_JOIN_OB
						endpar
					else
						par
							knowsAsymPubKey(self,messageField_nodeE_nodeA_1_PUB_KEY_REP_JOIN):=true
							messageField_nodeE_nodeA_1_PUB_KEY_REP_JOIN:=messageField_nodeB_nodeE_1_PUB_KEY_REP_JOIN
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
					if(messageField_nodeA_nodeE_1_KEX_SET=CSA_0)then
						par
							knowsAsymPubKey(self,messageField_nodeE_nodeB_1_PUB_KEY_REP_CTRL):=true
							messageField_nodeE_nodeB_1_PUB_KEY_REP_CTRL := messageField_nodeA_nodeE_1_PUB_KEY_REP_CTRL
						endpar
					else
						par
							knowsAsymPubKey(self,messageField_nodeE_nodeB_1_PUB_KEY_REP_CTRL_OB):=true
							messageField_nodeE_nodeB_1_PUB_KEY_REP_CTRL_OB := messageField_nodeA_nodeE_1_PUB_KEY_REP_CTRL_OB
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
				if(controllerState(self) = INSERT_PIN and  messageField_nodeA_nodeE_1_KEX_SET=CSA_0 and protocolMessage( $eslv ,self ) = PUB_KEY_REP_JOIN and abortCtrlSaved = false) then
					if(not(passed(TAI2)))then
						let($sk_ob =messageField_nodeE_nodeA_1_PUB_KEY_REP_JOIN_OB)in
							par
								controllerState(self) := WAIT_NONCE
								protocolMessage( self , $eslv ) := PUB_KEY_REP_CTRL
								messageField_nodeA_nodeE_1_PUB_KEY_REP_CTRL := KPUB_CTRL//readKnowledge(self,KPUB_CTRL)
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
					if(controllerState(self) = INSERT_PIN and  messageField_nodeA_nodeE_1_KEX_SET=CSA_1 and protocolMessage( $eslv ,self ) = PUB_KEY_REP_JOIN and abortCtrlSaved = false) then
						if(not(passed(TAI2)))then
							let($sk =messageField_nodeE_nodeA_1_PUB_KEY_REP_JOIN)in
								let($aes_1=diffieHellman($sk,KPRIV_CTRL))in
									par
										controllerState(self) := WAIT_NONCE
										protocolMessage( self , $eslv ) := PUB_KEY_REP_CTRL
										messageField_nodeA_nodeE_1_PUB_KEY_REP_CTRL_OB := OB_KEY_CTRL	
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
			
				if(slaveState(self) = INSERT_PIN_CSA and messageField_nodeE_nodeB_1_KEX_SET=CSA_0 and protocolMessage( $ectrl ,self ) = PUB_KEY_REP_CTRL and abortSlvSaved = false and not(passed(TBI1))) then
								let($skc=messageField_nodeE_nodeB_1_PUB_KEY_REP_CTRL)in
									let($aes_0=diffieHellman($skc,KPRIV_SLV))in
										par
											//slaveState(self) := WAIT_SLV_AES
											protocolMessage( self , $ectrl ) := NONCE_GET						
											slaveState(self) := WAIT_NONCE_REP_REI
											knowsSymKey(self,$aes_0):=true												
										endpar
									endlet
								endlet
						else
							if(slaveState(self) = INSERT_PIN_CSA and messageField_nodeE_nodeB_1_KEX_SET=CSA_1 and protocolMessage( $ectrl ,self ) = PUB_KEY_REP_CTRL and abortSlvSaved = false) then
								if(not(passed(TBI1)))then
										let($skcob=messageField_nodeE_nodeB_1_PUB_KEY_REP_CTRL_OB)in
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
					
					knowsAsymPubKey(self,messageField_nodeA_nodeE_1_PUB_KEY_REP_CTRL):=true
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
						messageField_nodeB_nodeE_1_EC_SEI_KEX_SET_ECHO:=messageField_nodeE_nodeB_1_KEX_SET
						messageField_nodeB_nodeE_2_EC_SEI_KEX_SET_ECHO:=messageField_nodeE_nodeB_2_KEX_SET
						messageField_nodeB_nodeE_3_EC_SEI_KEX_SET_ECHO:=messageField_nodeE_nodeB_3_KEX_SET
						messageField_nodeB_nodeE_4_EC_SEI_KEX_SET_ECHO:=messageField_nodeE_nodeB_4_KEX_SET
						messageField_nodeB_nodeE_5_EC_SEI_KEX_SET_ECHO:=messageField_nodeE_nodeB_5_KEX_SET
						messageField_nodeB_nodeE_6_EC_SEI_KEX_SET_ECHO:=messageField_nodeE_nodeB_6_KEX_SET
						messageField_nodeB_nodeE_7_EC_SEI_KEX_SET_ECHO:=messageField_nodeE_nodeB_7_KEX_SET
						protocolMessage( self , $ectrl ) := EC_SEI_KEX_SET_ECHO
						slaveState(self) := WAIT_KEX_REPORT_ECHO		
					endpar
				endif
			endif
		endlet
		
	rule  r_bruteForce=
		let ($slv=nodeB) in
			if(protocolMessage( $slv , self ) = EC_SEI_KEX_SET_ECHO and protocolMessage(  self, $slv) != EC_KEX_REPORT_ECHO  and cracked=false)then
				let($k=KPRIV_MITM_CTRL,$skc =messageField_nodeB_nodeE_1_PUB_KEY_REP_JOIN_OB)in
					
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
				let($kpriv = KPRIV_MITM_SLV,$skc = messageField_nodeA_nodeE_1_PUB_KEY_REP_CTRL) in	
					let($aes_0=diffieHellman($skc,$kpriv))in
						par
							knowsSymKey(self,$aes_0):=true
							symEnc(EC_SEI_KEX_SET_ECHO,1,1,7):=$aes_0
							protocolMessage( self , $ctrl ) := EC_SEI_KEX_SET_ECHO
							messageField_nodeE_nodeA_1_EC_SEI_KEX_SET_ECHO:=messageField_nodeA_nodeE_1_KEX_SET
							messageField_nodeE_nodeA_2_EC_SEI_KEX_SET_ECHO:=messageField_nodeA_nodeE_2_KEX_SET
							messageField_nodeE_nodeA_3_EC_SEI_KEX_SET_ECHO:=messageField_nodeA_nodeE_3_KEX_SET
							messageField_nodeE_nodeA_4_EC_SEI_KEX_SET_ECHO:=messageField_nodeA_nodeE_4_KEX_SET
							messageField_nodeE_nodeA_5_EC_SEI_KEX_SET_ECHO:=messageField_nodeA_nodeE_5_KEX_SET
							messageField_nodeE_nodeA_6_EC_SEI_KEX_SET_ECHO:=messageField_nodeA_nodeE_6_KEX_SET
							messageField_nodeE_nodeA_7_EC_SEI_KEX_SET_ECHO:=messageField_nodeA_nodeE_7_KEX_SET
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
					messageField_nodeE_nodeA_1_EC_SEI_KEX_SET_ECHO:=messageField_nodeB_nodeE_1_EC_SEI_KEX_SET_ECHO
					messageField_nodeE_nodeA_2_EC_SEI_KEX_SET_ECHO:=messageField_nodeB_nodeE_2_EC_SEI_KEX_SET_ECHO
					messageField_nodeE_nodeA_3_EC_SEI_KEX_SET_ECHO:=messageField_nodeB_nodeE_3_EC_SEI_KEX_SET_ECHO
					messageField_nodeE_nodeA_4_EC_SEI_KEX_SET_ECHO:=messageField_nodeB_nodeE_4_EC_SEI_KEX_SET_ECHO
					messageField_nodeE_nodeA_5_EC_SEI_KEX_SET_ECHO:=messageField_nodeB_nodeE_5_EC_SEI_KEX_SET_ECHO
					messageField_nodeE_nodeA_6_EC_SEI_KEX_SET_ECHO:=messageField_nodeB_nodeE_6_EC_SEI_KEX_SET_ECHO
					messageField_nodeE_nodeA_7_EC_SEI_KEX_SET_ECHO:=messageField_nodeB_nodeE_7_EC_SEI_KEX_SET_ECHO
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
							if(messageField_nodeA_nodeE_1_KEX_SET=messageField_nodeE_nodeA_1_EC_SEI_KEX_SET_ECHO and messageField_nodeA_nodeE_2_KEX_SET=messageField_nodeE_nodeA_2_EC_SEI_KEX_SET_ECHO
								and messageField_nodeA_nodeE_3_KEX_SET=messageField_nodeE_nodeA_3_EC_SEI_KEX_SET_ECHO and messageField_nodeA_nodeE_4_KEX_SET=messageField_nodeE_nodeA_4_EC_SEI_KEX_SET_ECHO
								and messageField_nodeA_nodeE_5_KEX_SET=messageField_nodeE_nodeA_5_EC_SEI_KEX_SET_ECHO and messageField_nodeA_nodeE_6_KEX_SET=messageField_nodeE_nodeA_6_EC_SEI_KEX_SET_ECHO
								and messageField_nodeA_nodeE_7_KEX_SET=messageField_nodeE_nodeA_7_EC_SEI_KEX_SET_ECHO)then
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
									messageField_nodeA_nodeE_1_EC_KEX_REPORT_ECHO:=messageField_nodeE_nodeA_1_KEX_REP
									messageField_nodeA_nodeE_2_EC_KEX_REPORT_ECHO:=messageField_nodeE_nodeA_2_KEX_REP
									messageField_nodeA_nodeE_3_EC_KEX_REPORT_ECHO:=messageField_nodeE_nodeA_3_KEX_REP
									messageField_nodeA_nodeE_4_EC_KEX_REPORT_ECHO:=messageField_nodeE_nodeA_4_KEX_REP
									messageField_nodeA_nodeE_5_EC_KEX_REPORT_ECHO:=messageField_nodeE_nodeA_5_KEX_REP
									messageField_nodeA_nodeE_6_EC_KEX_REPORT_ECHO:=messageField_nodeE_nodeA_6_KEX_REP
									messageField_nodeA_nodeE_7_EC_KEX_REPORT_ECHO:=messageField_nodeE_nodeA_7_KEX_REP
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
							if(messageField_nodeB_nodeE_1_KEX_REP=messageField_nodeE_nodeB_1_EC_KEX_REPORT_ECHO and messageField_nodeB_nodeE_2_KEX_REP=messageField_nodeE_nodeB_2_EC_KEX_REPORT_ECHO 
								and messageField_nodeB_nodeE_3_KEX_REP=messageField_nodeE_nodeB_3_EC_KEX_REPORT_ECHO and messageField_nodeB_nodeE_4_KEX_REP=messageField_nodeE_nodeB_4_EC_KEX_REPORT_ECHO
								and messageField_nodeB_nodeE_5_KEX_REP=messageField_nodeE_nodeB_5_EC_KEX_REPORT_ECHO and messageField_nodeB_nodeE_6_KEX_REP=messageField_nodeE_nodeB_6_EC_KEX_REPORT_ECHO
								and messageField_nodeB_nodeE_7_KEX_REP=messageField_nodeE_nodeB_7_EC_KEX_REPORT_ECHO)then
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
					messageField_nodeE_nodeB_1_EC_KEX_REPORT_ECHO:=messageField_nodeA_nodeE_1_EC_KEX_REPORT_ECHO
					messageField_nodeE_nodeB_2_EC_KEX_REPORT_ECHO:=messageField_nodeA_nodeE_2_EC_KEX_REPORT_ECHO
					messageField_nodeE_nodeB_3_EC_KEX_REPORT_ECHO:=messageField_nodeA_nodeE_3_EC_KEX_REPORT_ECHO
					messageField_nodeE_nodeB_4_EC_KEX_REPORT_ECHO:=messageField_nodeA_nodeE_4_EC_KEX_REPORT_ECHO
					messageField_nodeE_nodeB_5_EC_KEX_REPORT_ECHO:=messageField_nodeA_nodeE_5_EC_KEX_REPORT_ECHO
					messageField_nodeE_nodeB_6_EC_KEX_REPORT_ECHO:=messageField_nodeA_nodeE_6_EC_KEX_REPORT_ECHO
					messageField_nodeE_nodeB_7_EC_KEX_REPORT_ECHO:=messageField_nodeA_nodeE_7_EC_KEX_REPORT_ECHO
				endpar	
			endif
		endlet
			
	rule r_kexReportEchoCraft=
		let ($slv=nodeB)in
			if(protocolMessage( $slv ,self ) = EC_SEI_KEX_SET_ECHO and knowsSymKey(self,KT2)=true and protocolMessage( self , $slv ) != EC_KEX_REPORT_ECHO)then
				par
					protocolMessage( self , $slv ) := EC_KEX_REPORT_ECHO
					symEnc(EC_KEX_REPORT_ECHO,1,1,7):=KT2
					messageField_nodeE_nodeB_1_EC_KEX_REPORT_ECHO:=messageField_nodeB_nodeE_1_KEX_REP
					messageField_nodeE_nodeB_2_EC_KEX_REPORT_ECHO:=messageField_nodeB_nodeE_2_KEX_REP
					messageField_nodeE_nodeB_3_EC_KEX_REPORT_ECHO:=messageField_nodeB_nodeE_3_KEX_REP
					messageField_nodeE_nodeB_4_EC_KEX_REPORT_ECHO:=messageField_nodeB_nodeE_4_KEX_REP
					messageField_nodeE_nodeB_5_EC_KEX_REPORT_ECHO:=messageField_nodeB_nodeE_5_KEX_REP
					messageField_nodeE_nodeB_6_EC_KEX_REPORT_ECHO:=messageField_nodeB_nodeE_6_KEX_REP
					messageField_nodeE_nodeB_7_EC_KEX_REPORT_ECHO:=messageField_nodeB_nodeE_7_KEX_REP
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
		
	
	//Passive ATK properties
	/* Confidentiality */
	//CTLSPEC not(ef(mode=PASSIVE and knowsSymKey(nodeE,KT3)=true))
	//CTLSPEC not(ef(mode=PASSIVE and knowsBitString(nodeE,PIN_OK)=true))
	/* Integrity */	
	//CTLSPEC not(ef(mode=PASSIVE and messageField_nodeB_nodeE_1_KEX_REP!=messageField_nodeE_nodeA_1_KEX_REP and protocolMessage(nodeE,nodeA)=KEX_REP))
	//CTLSPEC not(ef(mode=PASSIVE and messageField_nodeA_nodeE_1_KEX_SET!=messageField_nodeE_nodeB_1_KEX_SET and protocolMessage(nodeE,nodeB)=KEX_SET))
	/* Authentication */
	//CTLSPEC ef(mode=PASSIVE and knowsAsymPubKey(nodeB,KPUB_SLV)=true and knowsBitString(nodeA,PIN_OK)=true) implies ag(not(knowsBitString(nodeE,PIN_OK)=true))
	/*State Reachability*/
	//CTLSPEC not(ef(mode=PASSIVE and controllerState(nodeA)=OK_C and slaveState(nodeB)=OK_S and slave(nodeB)=ALARM_UP))
	//CTLSPEC not(ef(mode=PASSIVE and controllerState(nodeA)=OK_C and slaveState(nodeB)=OK_S))
	
	//Active ATK properties
	/* Confidentiality */
	//CTLSPEC not(ef(mode=ACTIVE and knowsSymKey(nodeE,KT1)=true))
	//CTLSPEC not(ef(mode=ACTIVE and knowsSymKey(nodeE,KT2)=true))
	//CTLSPEC not(ef(mode=ACTIVE and knowsBitString(nodeE,PIN_OK)=true))
	/* Integrity */	
	//CTLSPEC not(ef(mode=ACTIVE and messageField_nodeB_nodeE_4_KEX_REP!=messageField_nodeE_nodeA_4_KEX_REP and protocolMessage(nodeE,nodeA)=KEX_REP))
	//CTLSPEC not(ef(mode=ACTIVE and messageField_nodeA_nodeE_1_KEX_SET!=messageField_nodeE_nodeB_1_KEX_SET and protocolMessage(nodeE,nodeB)=KEX_SET))
	/* Authentication */
	//CTLSPEC ef(mode=ACTIVE and knowsAsymPubKey(nodeB,KPUB_SLV)=true and knowsBitString(nodeA,PIN_OK)=true) implies ag(not(knowsBitString(nodeE,PIN_OK)=true))
	/*State Reachability*/
	//CTLSPEC not(ef(mode=ACTIVE and controllerState(nodeA)=OK_C and slaveState(nodeB)=OK_S and slave(nodeB)=ALARM_UP))
	CTLSPEC not(ef(mode=ACTIVE and controllerState(nodeA)=OK_C and slaveState(nodeB)=OK_S))
	//CTLSPEC not(ef(mode=ACTIVE and controllerState(nodeA)=OK_C and slaveState(nodeB)=OK_S and knowsBitString(nodeE,PIN_ERROR)=true))
	//CTLSPEC not(ef(mode=ACTIVE and qrCodeUseDecison and knowsSymKey(nodeA,KT3)=true ))
	
	//CTLSPEC not(ef(mode=ACTIVE and controllerState(nodeA)=ERROR_C))
	//CTLSPEC not(ef(mode=ACTIVE and controllerState(nodeA)=OK_C and slaveState(nodeB)=OK_S and qrKey=KPUB_SLV and qrCodeUseDecison=true))
	//CTLSPEC not(ef(mode=ACTIVE and controllerState(nodeA)=OK_C and slaveState(nodeB)=OK_S and qrCodeUseDecison=true))
	
	//CTLSPEC not(ef(messageField_nodeB_nodeE_1_KEX_REP!=messageField_nodeE_nodeA_1_KEX_REP and mode=PASSIVE and protocolMessage(nodeE,nodeA)=KEX_REP))
	
	//CTLSPEC ef(knowsAsymPubKey(nodeB,KPUB_SLV)=true and knowsBitString(nodeA,PIN_OK)=true) implies ag(not(knowsBitString(nodeE,PIN_OK)=true))
	
	//CTLSPEC not(ef(knowsSymKey(nodeA,KT1)=true ))	
	//CTLSPEC not(ef(knowsSymKey(nodeB,KT2)=true ))
	//CTLSPEC not(ef(knowsSymKey(nodeE,KT2)=true ))		
	//CTLSPEC not(ef( abortSlvSaved = false and slaveState(nodeB) = INSERT_PIN_CSA and sessionKnowledge_nodeB_nodeE_1_KEX_SET=false and protocolMessage( nodeE ,nodeB ) = PUB_KEY_REP_CTRL and passed(TBI1)=false))
	//CTLSPEC not(ef( slaveState(nodeB)=OK_S))
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
	function knowsAsymPubKey($s in Receiver, $ks in KnowledgeAsymPubKey)=
			switch $ks
				case KPUB_SLV: true
				case OB_KEY_SLV: true
				otherwise false
			endswitch
	function knowsAsymPubKey($c in Initiator, $kc in KnowledgeAsymPubKey)=if($kc=KPUB_CTRL or $kc=OB_KEY_CTRL ) then true else false endif
	function knowsAsymPubKey($e in Intruder, $ke in KnowledgeAsymPubKey)=if($ke=OB_KEY_MITM_CTRL or $ke=OB_KEY_MITM_SLV or $ke=KPUB_MITM_SLV or $ke=KPUB_MITM_CTRL) then true else false endif
	function knowsAsymPrivKey($s in Receiver, $ks in KnowledgeAsymPrivKey)=if($ks=KPRIV_SLV) then true else false endif
	function knowsAsymPrivKey($c in Initiator, $kc in KnowledgeAsymPrivKey)=if($kc=KPRIV_CTRL) then true else false endif
	function knowsAsymPrivKey($e in Intruder, $ke in KnowledgeAsymPrivKey)=if($ke=KPRIV_MITM_CTRL and $ke=KPRIV_MITM_SLV) then true else false endif
	function knowsSymKey($e in Intruder, $ke in KnowledgeSymKey)=false
	function knowsSymKey($c in Initiator, $kc in KnowledgeSymKey)=false
	function knowsSymKey($s in Receiver, $ks in KnowledgeSymKey)=false
	function knowsBitString($e in Intruder, $ke in KnowledgeBitString)=false
	function knowsBitString($c in Initiator, $kc in KnowledgeBitString)=false
	function knowsBitString($s in Receiver, $ks in KnowledgeBitString)=false
	function  protocolMessage($i in Initiator,$e in Intruder)= EMPTY
	function  protocolMessage($e in Intruder, $i in Initiator)= EMPTY
	function  protocolMessage($r in Receiver,$e in Intruder)= EMPTY
	function  protocolMessage($e in Intruder,$r in Receiver)= EMPTY
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
	//function messageField_1_KEX_REP=true
	
	agent Initiator:		
			r_controllerRule[]
			
	agent Intruder:		
			r_mitmRule[]
				
	agent Receiver:
			r_slaveRule[]
			
			
