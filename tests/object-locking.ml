(*
 * Analyse libvirt driver API methods for mutex locking mistakes
 *
 * Copyright (C) 2008-2010 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 *)

open Pretty
open Cil

(*
 * Convenient routine to load the contents of a file into
 * a list of strings
 *)
let input_file filename =
  let chan = open_in filename in
  let lines = ref [] in
  try while true; do lines := input_line chan :: !lines done; []
  with
    End_of_file -> close_in chan; List.rev !lines

module DF = Dataflow
module UD = Usedef
module IH = Inthash
module E = Errormsg
module VS = UD.VS

let debug = ref false


let driverTables = [
  "virDriver";
  "virNetworkDriver";
  "virStorageDriver";
  "virDeviceMonitor";
(*  "virStateDriver"; Disable for now, since shutdown/startup have weird locking rules *)
]

(*
 * This is the list of all libvirt methods which return
 * pointers to locked objects
 *)
let lockedObjMethods = [
   "virDomainFindByID";
   "virDomainFindByUUID";
   "virDomainFindByName";
   "virDomainAssignDef";

   "virNetworkFindByUUID";
   "virNetworkFindByName";
   "virNetworkAssignDef";

   "virNodeDeviceFindByName";
   "virNodeDeviceAssignDef";

   "virStoragePoolObjFindByUUID";
   "virStoragePoolObjFindByName";
   "virStoragePoolObjAssignDef"
]


(*
 * This is the list of all libvirt methods which
 * can release an object lock. Technically we
 * ought to pair them up correctly with previous
 * ones, but the compiler can already complain
 * about passing a virNetworkObjPtr to a virDomainObjUnlock
 * method so lets be lazy
 *)
let objectLockMethods = [
   "virDomainObjLock";
   "virNetworkObjLock";
   "virStoragePoolObjLock";
   "virNodeDevObjLock"
]

(*
 * This is the list of all libvirt methods which
 * can release an object lock. Technically we
 * ought to pair them up correctly with previous
 * ones, but the compiler can already complain
 * about passing a virNetworkObjPtr to a virDomainObjUnlock
 * method so lets be lazy
 *)
let objectUnlockMethods = [
   "virDomainObjUnlock";
   "virNetworkObjUnlock";
   "virStoragePoolObjUnlock";
   "virNodeDevObjUnlock"
]

(*
 * The data types that the previous two sets of
 * methods operate on
 *)
let lockableObjects = [
      "virDomainObjPtr";
      "virNetworkObjPtr";
      "virStoragePoolObjPtr";
      "virNodeDevObjPtr"
]



(*
 * The methods which globally lock an entire driver
 *)
let driverLockMethods = [
    "qemuDriverLock";
    "openvzDriverLock";
    "testDriverLock";
    "lxcDriverLock";
    "umlDriverLock";
    "nodedevDriverLock";
    "networkDriverLock";
    "storageDriverLock";
    "oneDriverLock"
]

(*
 * The methods which globally unlock an entire driver
 *)
let driverUnlockMethods = [
    "qemuDriverUnlock";
    "openvzDriverUnlock";
    "testDriverUnlock";
    "lxcDriverUnlock";
    "umlDriverUnlock";
    "nodedevDriverUnlock";
    "networkDriverUnlock";
    "storageDriverUnlock";
    "oneDriverUnlock"
]

(*
 * The data types that the previous two sets of
 * methods operate on. These may be structs or
 * typedefs, we don't care
 *)
let lockableDrivers = [
      "qemud_driver";
      "openvz_driver";
      "testConnPtr";
      "lxc_driver_t";
      "uml_driver";
      "virStorageDriverStatePtr";
      "network_driver";
      "virDeviceMonitorState";
      "one_driver_t";
]


let isFuncCallLval lval methodList =
   match lval with
      Var vi, o ->
          List.mem vi.vname methodList
      | _ -> false

let isFuncCallExp exp methodList =
   match exp with
       Lval lval ->
          isFuncCallLval lval methodList
       | _ -> false

let isFuncCallInstr instr methodList =
   match instr with
       Call (retval,exp,explist,srcloc) ->
         isFuncCallExp exp methodList
       | _ -> false



let findDriverFunc init =
   match init with
       SingleInit (exp) -> (
         match exp with
           AddrOf (lval) -> (
              match lval with
                  Var vi, o ->
                    true
                | _ -> false
           )
           | _ -> false
       )
     | _ ->false

let findDriverFuncs init =
   match init with
      CompoundInit (typ, list) ->
           List.filter (
              fun l ->
                 match l with
                   (offset, init) ->
                       findDriverFunc init

          ) list;
      | _ -> ([])


let getDriverFuncs initinfo =
   match initinfo.init with
      Some (i) ->
        let ls = findDriverFuncs i in
        ls
     | _ -> []

let getDriverFuncName init =
   match init with
       SingleInit (exp) -> (
         match exp with
           AddrOf (lval) -> (
              match lval with
                Var vi, o ->

                    vi.vname
                | _ -> "unknown"
           )
           | _ -> "unknown"
       )
     | _ -> "unknown"


let getDriverFuncNames initinfo =
   List.map (
       fun l ->
         match l with
            (offset, init) ->
               getDriverFuncName init
   ) (getDriverFuncs initinfo)


(*
 * Convenience methods which take a Cil.Instr object
 * and ask whether its associated with one of the
 * method sets defined earlier
 *)
let isObjectFetchCall instr =
   isFuncCallInstr instr lockedObjMethods

let isObjectLockCall instr =
   isFuncCallInstr instr objectLockMethods

let isObjectUnlockCall instr =
   isFuncCallInstr instr objectUnlockMethods

let isDriverLockCall instr =
   isFuncCallInstr instr driverLockMethods

let isDriverUnlockCall instr =
   isFuncCallInstr instr driverUnlockMethods


let isWantedType typ typeList =
    match typ with
      TNamed (tinfo, attrs) ->
         List.mem tinfo.tname typeList
      | TPtr (ptrtyp, attrs) ->
         let f = match ptrtyp with
           TNamed (tinfo2, attrs) ->
               List.mem tinfo2.tname typeList
           | TComp (cinfo, attrs) ->
               List.mem cinfo.cname typeList
           | _ ->
               false in
         f
      | _ -> false

(*
 * Convenience methods which take a Cil.Varinfo object
 * and ask whether it matches a variable datatype that
 * we're interested in tracking for locking purposes
 *)
let isLockableObjectVar varinfo =
    isWantedType varinfo.vtype lockableObjects

let isLockableDriverVar varinfo =
    isWantedType varinfo.vtype lockableDrivers

let isDriverTable varinfo =
    isWantedType varinfo.vtype driverTables


(*
 * Take a Cil.Exp object (ie an expression) and see whether
 * the expression corresponds to a check for NULL against
 * one of our interesting objects
 * eg
 *
 *     if (!vm) ...
 *
 * For a variable 'virDomainObjPtr vm'
 *)
let isLockableThingNull exp funcheck =
   match exp with
     | UnOp (op,exp,typ) -> (
         match op with
           LNot -> (
             match exp with
               Lval (lhost, off) -> (
                  match lhost with
                    Var vi ->
                      funcheck vi
                    | _ -> false
                 )
               | _ -> false
            )
          | _ -> false
         )
      | _ ->
          false

let isLockableObjectNull exp =
   isLockableThingNull exp isLockableObjectVar

let isLockableDriverNull exp =
   isLockableThingNull exp isLockableDriverVar


(*
 * Prior to validating a function, initialize these
 * to VS.empty
 *
 * They contain the list of driver and object variables
 * objects declared as local variables
 *
 *)
let lockableObjs: VS.t ref  = ref VS.empty
let lockableDriver: VS.t ref  = ref VS.empty

(*
 * Given a Cil.Instr object (ie a single instruction), get
 * the list of all used & defined variables associated with
 * it. Then caculate intersection with the driver and object
 * variables we're interested in tracking and return four sets
 *
 * List of used driver variables
 * List of defined driver variables
 * List of used object variables
 * List of defined object variables
 *)
let computeUseDefState i =
    let u, d = UD.computeUseDefInstr i in
    let useo = VS.inter u !lockableObjs in
    let defo = VS.inter d !lockableObjs in
    let used = VS.inter u !lockableDriver in
    let defd = VS.inter d !lockableDriver in
    (used, defd, useo, defo)


(* Some crude helpers for debugging this horrible code *)
let printVI vi =
    ignore(printf "      | %a %s\n" d_type vi.vtype vi.vname)

let printVS vs =
    VS.iter printVI vs


let prettyprint2 stmdat () (_, ld, ud, lo, ui, uud, uuo, loud, ldlo, dead) =
     text ""


type ilist = Cil.instr list

(*
 * This module implements the Cil.DataFlow.ForwardsTransfer
 * interface. This is what 'does the interesting stuff'
 * when walking over a function's code paths
 *)
module Locking = struct
  let name = "Locking"
  let debug = debug

  (*
   * Our state currently consists of
   *
   *  The set of driver variables that are locked
   *  The set of driver variables that are unlocked
   *  The set of object variables that are locked
   *  The set of object variables that are unlocked
   *
   * Lists of Cil.Instr for:
   *
   *   Instrs using an unlocked driver variable
   *   Instrs using an unlocked object variable
   *   Instrs locking a object variable while not holding a locked driver variable
   *   Instrs locking a driver variable while holding a locked object variable
   *   Instrs causing deadlock by fetching a lock object, while an object is already locked
   *
   *)
  type t = (unit * VS.t * VS.t * VS.t * VS.t * ilist * ilist * ilist * ilist * ilist)

  (* This holds an instance of our state data, per statement *)
  let stmtStartData = IH.create 32

  let pretty =
    prettyprint2 stmtStartData

  let copy (_, ld, ud, lo, uo, uud, uuo, loud, ldlo, dead) =
      ((), ld, ud, lo, uo, uud, uuo, loud, ldlo, dead)

  let computeFirstPredecessor stm (_, ld, ud, lo, uo, uud, uuo, loud, ldlo, dead) =
    ((), ld, ud, lo, uo, uud, uuo, loud, ldlo, dead)


  (*
   * Merge existing state for a statement, with new state
   *
   * If new and old state is the same, this returns None,
   * If they are different, then returns the union.
   *)
  let combinePredecessors (stm:stmt) ~(old:t) ((_, ldn, udn, lon, uon, uudn, uuon, loudn, ldlon, deadn):t) =
     match old with (_, ldo, udo, loo,uoo, uudo, uuoo, loudo, ldloo, deado)-> begin
     let lde= (VS.equal ldo ldn) || ((VS.is_empty ldo) && (VS.is_empty ldn)) in
     let ude= VS.equal udo udn || ((VS.is_empty udo) && (VS.is_empty udn)) in
     let loe= VS.equal loo lon || ((VS.is_empty loo) && (VS.is_empty lon)) in
     let uoe= VS.equal uoo uon || ((VS.is_empty uoo) && (VS.is_empty uon)) in

     if lde && ude && loe && uoe then
         None
     else (
         let ldret = VS.union ldo ldn in
         let udret = VS.union udo udn in
         let loret = VS.union loo lon in
         let uoret = VS.union uoo uon in
         Some ((), ldret, udret, loret, uoret, uudn, uuon, loudn, ldlon, deadn)
     )
     end


  (*
   * This handles a Cil.Instr object. This is sortof a C level statement.
   *)
  let doInstr i (_, ld, ud, lo, uo, uud, uuo, loud, ldlo, dead) =
     let transform (_, ld, ud, lo, uo, uud, uuo, loud, ldlo, dead) =
         let used, defd, useo, defo = computeUseDefState i in


         if isDriverLockCall i then (
            (*
             * A driver was locked, so add to the list of locked
	     * driver variables, and remove from the unlocked list
	     *)
            let retld = VS.union ld used in
            let retud = VS.diff ud used in

            (*
	     * Report if any objects are locked already since
	     * thats a deadlock risk
	     *)
            if VS.is_empty lo then
               ((), retld, retud, lo, uo, uud, uuo, loud, ldlo, dead)
            else
               ((), retld, retud, lo, uo, uud, uuo, loud, List.append ldlo [i], dead)
         ) else if isDriverUnlockCall i then (
            (*
             * A driver was unlocked, so add to the list of unlocked
	     * driver variables, and remove from the locked list
	     *)
            let retld = VS.diff ld used in
            let retud = VS.union ud used in

            ((), retld, retud, lo, uo, uud, uuo, loud, ldlo, dead);
         ) else if isObjectFetchCall i then (
            (*
             * A object was fetched & locked, so add to the list of
	     * locked driver variables. Nothing to remove from unlocked
	     * list here.
	     *
	     * XXX, not entirely true. We should check if they're
	     * blowing away an existing non-NULL value in the lval
	     * really.
	     *)
            let retlo = VS.union lo defo in

            (*
	     * Report if driver is not locked, since that's a safety
	     * risk
	     *)
            if VS.is_empty ld then (
	       if VS.is_empty lo then (
                 ((), ld, ud, retlo, uo, uud, uuo, List.append loud [i], ldlo, dead)
               ) else (
                 ((), ld, ud, retlo, uo, uud, uuo, List.append loud [i], ldlo, List.append dead [i])
               )
            ) else (
	       if VS.is_empty lo then (
                 ((), ld, ud, retlo, uo, uud, uuo, loud, ldlo, dead)
               ) else (
                 ((), ld, ud, retlo, uo, uud, uuo, loud, ldlo, List.append dead [i])
               )
            )
         ) else if isObjectLockCall i then (
            (*
             * A driver was locked, so add to the list of locked
	     * driver variables, and remove from the unlocked list
	     *)
            let retlo = VS.union lo useo in
            let retuo = VS.diff uo useo in

            (*
	     * Report if driver is not locked, since that's a safety
	     * risk
	     *)
            if VS.is_empty ld then
               ((), ld, ud, retlo, retuo, uud, uuo, List.append loud [i], ldlo, dead)
            else
               ((), ld, ud, retlo, retuo, uud, uuo, loud, ldlo, dead)
         ) else if isObjectUnlockCall i then (
            (*
             * A object was unlocked, so add to the list of unlocked
	     * driver variables, and remove from the locked list
	     *)
            let retlo = VS.diff lo useo in
            let retuo = VS.union uo useo in
            ((), ld, ud, retlo, retuo, uud, uuo, loud, ldlo, dead);
         ) else (
            (*
             * Nothing special happened, at best an assignment.
	     * So add any defined variables to the list of unlocked
	     * object or driver variables.
	     * XXX same edge case as isObjectFetchCall about possible
	     * overwriting
	     *)
            let retud = VS.union ud defd in
            let retuo = VS.union uo defo in

	    (*
	     * Report is a driver is used while unlocked
	     *)
            let retuud =
               if not (VS.is_empty used) && (VS.is_empty ld) then
                  List.append uud [i]
               else
                  uud in
	    (*
	     * Report is a object is used while unlocked
	     *)
            let retuuo =
               if not (VS.is_empty useo) && (VS.is_empty lo) then
                  List.append uuo [i]
               else
                  uuo in

            ((), ld, retud, lo, retuo, retuud, retuuo, loud, ldlo, dead)
         );
       in

    DF.Post transform

  (*
   * This handles a Cil.Stmt object. This is sortof a C code block
   *)
  let doStmt stm (_, ld, ud, lo, uo, uud, uuo, loud, ldlo, dead) =
     DF.SUse ((), ld, ud, lo, uo, [], [], [], [], [])


  (*
   * This handles decision making for a conditional statement,
   * ie an if (foo). It is called twice for each conditional
   * ie, once per possible choice.
   *)
  let doGuard exp (_, ld, ud, lo, uo, uud, uuo, loud, ldlo, dead) =
     (*
      * If we're going down a branch where our object variable
      * is set to NULL, then we must remove it from the
      * list of locked objects. This handles the case of...
      *
      * vm = virDomainFindByUUID(..)
      * if (!vm) {
      *     .... this code branch ....
      * } else {
      *     .... leaves default handling for this branch ...
      * }
      *)
     let lonull = UD.computeUseExp exp in

     let loret =
       if isLockableObjectNull exp then
          VS.diff lo lonull
       else
          lo in
     let uoret =
       if isLockableObjectNull exp then
          VS.union uo lonull
       else
          uo in
     let ldret =
       if isLockableDriverNull exp then
          VS.diff ld lonull
       else
          ld in
     let udret =
       if isLockableDriverNull exp then
          VS.union ud lonull
       else
          ud in

     DF.GUse ((), ldret, udret, loret, uoret, uud, uuo, loud, ldlo, dead)

  (*
   * We're not filtering out any statements
   *)
  let filterStmt stm = true

end

module L = DF.ForwardsDataFlow(Locking)

let () =
  (* Read the list of files from "libvirt-files". *)
  let files = input_file "object-locking-files.txt" in

  (* Load & parse each input file. *)
  let files =
    List.map (
      fun filename ->
	(* Why does parse return a continuation? *)
	let f = Frontc.parse filename in
	f ()
    ) files in

  (* Merge them. *)
  let file = Mergecil.merge files "test" in

  (* Do control-flow-graph analysis. *)
  Cfg.computeFileCFG file;

  print_endline "";

  let driverVars = List.filter (
    function
    | GVar (varinfo, initinfo, loc) -> (* global variable *)
      let name = varinfo.vname in
      if isDriverTable varinfo then
        true
      else
         false
    | _ -> false
  ) file.globals in

  let driverVarFuncs = List.map (
    function
    | GVar (varinfo, initinfo, loc) -> (* global variable *)
      let name = varinfo.vname in
      if isDriverTable varinfo then
        getDriverFuncNames initinfo
      else
        []
    | _ -> []
  ) driverVars in

  let driverFuncsAll = List.flatten driverVarFuncs in
  let driverFuncsSkip = [
      "testClose";
      "openvzClose";
  ] in
  let driverFuncs = List.filter (
     fun st ->
         if List.mem st driverFuncsSkip then
            false
         else
            true
  ) driverFuncsAll in

  (*
   * Now comes our fun.... iterate over every global symbol
   * definition Cfg found..... but...
   *)
  List.iter (
    function
    (* ....only care about functions *)
    | GFun (fundec, loc) -> (* function definition *)
      let name = fundec.svar.vname in

      if List.mem name driverFuncs then (
         (* Initialize list of driver & object variables to be empty *)
	 ignore (lockableDriver = ref VS.empty);
	 ignore (lockableObjs = ref VS.empty);

         (*
          * Query all local variables, and figure out which correspond
          * to interesting driver & object variables we track
          *)
         List.iter (
              fun var ->
                if isLockableDriverVar var then
                   lockableDriver := VS.add var !lockableDriver
                else if isLockableObjectVar var then
                   lockableObjs := VS.add var !lockableObjs;
          ) fundec.slocals;

         List.iter (
              fun gl ->
                 match gl with
                   GVar (vi, ii, loc) ->
                     if isLockableDriverVar vi then
                        lockableDriver := VS.add vi !lockableDriver
                  | _ -> ()
         ) file.globals;

         (*
          * Initialize the state for each statement (ie C code block)
          * to be empty
          *)
         List.iter (
         fun st ->
             IH.add Locking.stmtStartData st.sid ((),
                       VS.empty, VS.empty, VS.empty, VS.empty,
                       [], [], [], [], [])
         ) fundec.sallstmts;

         (*
          * This walks all the code paths in the function building
          * up the state for each statement (ie C code block)
          * ie, this is invoking the "Locking" module we created
          * earlier
          *)
         L.compute fundec.sallstmts;

         (*
          * Find all statements (ie C code blocks) which have no
          * successor statements. This means they are exit points
          * in the function
          *)
         let exitPoints = List.filter (
                     fun st ->
                       List.length st.succs = 0
                    ) fundec.sallstmts in

         (*
          * For each of the exit points, check to see if there are
          * any with locked driver or object variables & grab them
          *)
         let leaks = List.filter (
		       fun st ->
			   let (_, ld, ud, lo, uo, uud, uuo, loud, ldlo, dead) =
                                   IH.find Locking.stmtStartData st.sid in
			   let leakDrivers = not (VS.is_empty ld) in
			   let leakObjects = not (VS.is_empty lo) in
			   leakDrivers or leakObjects
                     ) exitPoints in

         let mistakes = List.filter (
		       fun st ->
			   let (_, ld, ud, lo, uo, uud, uuo, loud, ldlo, dead) =
                                   IH.find Locking.stmtStartData st.sid in
                           let lockDriverOrdering = (List.length ldlo) > 0 in
                           let lockObjectOrdering = (List.length loud) > 0 in

                           let useDriverUnlocked = (List.length uud) > 0 in
                           let useObjectUnlocked = (List.length uuo) > 0 in

			   let deadLocked = (List.length dead) > 0 in

			   lockDriverOrdering or lockObjectOrdering or useDriverUnlocked or useObjectUnlocked or deadLocked
                     ) fundec.sallstmts in

         if (List.length leaks) > 0 || (List.length mistakes) > 0 then (
		print_endline "================================================================";
		ignore (printf "Function: %s\n" name);
		print_endline "----------------------------------------------------------------";
		ignore (printf "  - Total exit points with locked vars: %d\n" (List.length leaks));

		(*
		 * Finally tell the user which exit points had locked varaibles
		 * And show them the line number and code snippet for easy fixing
		 *)
		List.iter (
			fun st ->
			    ignore (Pretty.printf "  - At exit on %a\n^^^^^^^^^\n" d_stmt st);
			    let (_, ld, ud, lo, uo, uud, uuo, loud, ldlo, dead) =
                            IH.find Locking.stmtStartData st.sid in
			    print_endline "    variables still locked are";
			    printVS ld;
			    printVS lo
			    ) leaks;


		ignore (printf "  - Total blocks with lock ordering mistakes: %d\n" (List.length mistakes));
		List.iter (
			fun st ->
			    let (_, ld, ud, lo, uo, uud, uuo, loud, ldlo, dead) =
			    IH.find Locking.stmtStartData st.sid in
			    List.iter (
				fun i ->
				    ignore (Pretty.printf "  - Driver locked while object is locked on %a\n" d_instr i);
				) ldlo;
			    List.iter (
				fun i ->
				    ignore (Pretty.printf "  - Object locked while driver is unlocked on %a\n" d_instr i);
				) loud;
			    List.iter (
				fun i ->
				    ignore (Pretty.printf "  - Driver used while unlocked on %a\n" d_instr i);
				) uud;
			    List.iter (
				fun i ->
				    ignore (Pretty.printf "  - Object used while unlocked on %a\n" d_instr i);
			    ) uuo;
			    List.iter (
				fun i ->
				    ignore (Pretty.printf "  - Object fetched while locked objects exist %a\n" d_instr i);
			    ) dead;
		) mistakes;
		print_endline "================================================================";
		print_endline "";
		print_endline "";
	  );

         ()
      )
    | _ -> ()
  ) file.globals;
