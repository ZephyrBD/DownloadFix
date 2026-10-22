using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

// PCL type names, method names and string literals appearing in this file are
// used solely to locate the corresponding instructions inside the target binary.
// Their rights belong to the original author, LTCatt:
//   https://github.com/Meloong-Git/PCL
// This repository ships no PCL source code or binaries and is not affiliated
// with the official PCL project.

class PatchModpack
{
    const string ComplianceMsg = "为遵守相关法律法规，PCL 暂时不再提供 MC 下载功能，非常抱歉 qwq……";

    static TypeDef t;
    static ModuleDef m;

    static MethodDef M(string name, int pc)
    {
        var md = t.Methods.FirstOrDefault(x => x.Name == name && x.MethodSig.Params.Count == pc);
        if (md == null) throw new Exception("method not found: " + name + "/" + pc);
        return md;
    }

    static void Main(string[] args)
    {
        string inPath = args[0], outPath = args[1];
        bool noFilter = args.Length > 2 && args[2] == "nofilter";
        bool keepStack = args.Length > 3 && args[3] == "keepstack";
        m = ModuleDefMD.Load(inPath);
        t = (TypeDef)m.Find("PCL.ModModpack", false);
        if (t == null) throw new Exception("target type not found");

        PatchDispatch();
        PatchEntry(noFilter, keepStack);
        PatchDetailClick();

        m.Write(outPath);
        Console.WriteLine("written: " + outPath);
    }

    static void PatchDispatch()
    {
        var md = M("ModpackInstall", 3);
        var body = md.Body;
        var il = body.Instructions;

        int idx = -1;
        for (int i = 0; i + 2 < il.Count; i++)
        {
            if (il[i].OpCode == OpCodes.Ldstr && (string)il[i].Operand == ComplianceMsg &&
                il[i + 1].OpCode == OpCodes.Newobj && il[i + 2].OpCode == OpCodes.Throw)
            { idx = i; break; }
        }
        if (idx < 0) throw new Exception("marker not found (already applied?)");

        IMethod logInfo = null;
        string srcPath = null;
        foreach (var ins in il)
        {
            if (ins.OpCode == OpCodes.Call && ins.Operand is IMethod)
            {
                var mm = (IMethod)ins.Operand;
                if (mm.Name == "Info" && mm.DeclaringType.Name == "Logger") logInfo = mm;
            }
            if (ins.OpCode == OpCodes.Ldstr && ((string)ins.Operand).StartsWith("E:\\Projects\\PCL"))
                srcPath = (string)ins.Operand;
        }
        if (logInfo == null) throw new Exception("logger reference not found");

        var vResult = body.Variables[0];   // LoaderCombo
        var vArchive = body.Variables[1];  // ZipArchive
        var vBase = body.Variables[2];     // ArchiveBaseFolder
        var vPack = body.Variables[4];     // PackType
        var epilogue = Instruction.Create(OpCodes.Ldloc, vResult);
        var ret = Instruction.Create(OpCodes.Ret);

        Func<string, MethodDef, bool, bool, List<Instruction>> makeCase =
            (logText, target, withInstance, withLogo) =>
        {
            var list = new List<Instruction>();
            if (logText != null)
            {
                list.Add(Instruction.Create(OpCodes.Ldstr, logText));
                list.Add(Instruction.Create(OpCodes.Ldc_I4_0));
                list.Add(Instruction.Create(OpCodes.Ldstr, srcPath ?? ""));
                list.Add(Instruction.Create(OpCodes.Call, logInfo));
            }
            list.Add(Instruction.Create(OpCodes.Ldarg_0));   // File
            list.Add(Instruction.Create(OpCodes.Ldloc, vArchive));
            if (target.MethodSig.Params.Count >= 3) list.Add(Instruction.Create(OpCodes.Ldloc, vBase));
            if (withInstance) list.Add(Instruction.Create(OpCodes.Ldarg_1));
            if (withLogo) list.Add(Instruction.Create(OpCodes.Ldarg_2));
            list.Add(Instruction.Create(OpCodes.Call, target));
            list.Add(Instruction.Create(OpCodes.Stloc, vResult));
            list.Add(Instruction.Create(OpCodes.Leave, epilogue));
            return list;
        };

        var caseInstrs = new List<List<Instruction>>();
        caseInstrs.Add(makeCase("整合包种类：CurseForge", M("InstallPackCurseForge", 5), true, true));
        caseInstrs.Add(makeCase("整合包种类：HMCL", M("InstallPackHMCL", 3), false, false));
        caseInstrs.Add(makeCase("整合包种类：MMC", M("InstallPackMMC", 3), false, false));
        caseInstrs.Add(makeCase("整合包种类：MCBBS", M("InstallPackMCBBS", 4), true, false));
        caseInstrs.Add(makeCase("整合包种类：Modrinth", M("InstallPackModrinth", 5), true, true));
        caseInstrs.Add(makeCase("整合包种类：带启动器的压缩包", M("InstallPackLauncherPack", 3), false, false));

        var defaultBlock = makeCase("整合包种类：未能识别，假定为压缩包", M("InstallPackCompress", 2), false, false);

        il[idx].OpCode = OpCodes.Ldloc;
        il[idx].Operand = vPack;
        il[idx + 1].OpCode = OpCodes.Switch;
        il[idx + 2].OpCode = OpCodes.Nop;
        il[idx + 2].Operand = null;

        int insertAt = idx + 3;
        foreach (var ins in defaultBlock) il.Insert(insertAt++, ins);

        var targets = new Instruction[caseInstrs.Count];
        for (int k = 0; k < caseInstrs.Count; k++)
        {
            targets[k] = caseInstrs[k][0];
            foreach (var ins in caseInstrs[k]) il.Insert(insertAt++, ins);
        }
        il[idx + 1].Operand = targets;
        
        
        foreach (var eh in body.ExceptionHandlers)
            if (eh.HandlerEnd == null) eh.HandlerEnd = epilogue;
        il.Add(epilogue);
        il.Add(ret);

        body.MaxStack = (ushort)Math.Max((int)body.MaxStack, 6);
        body.UpdateInstructionOffsets();
        Console.WriteLine("dispatch: instrs=" + il.Count);
    }

    static void PatchEntry(bool noFilter, bool keepStack)
    {
        var md = M("ModpackInstall", 0);
        var body = md.Body;
        var il = body.Instructions;

        var closureType = t.NestedTypes.FirstOrDefault(n => n.Name == "_Closure$__0-0");
        if (closureType == null) throw new Exception("closure type not found");
        var closureCtor = closureType.FindMethod(".ctor");
        var lambda = closureType.FindMethod("_Lambda$__0");
        var fileField = closureType.Fields.FirstOrDefault(f => f.Name == "$VB$Local_File");
        if (closureCtor == null || lambda == null || fileField == null)
            throw new Exception("unexpected closure layout");

        var selectFile = FindMemberRef("MeloongCore.Wpf.Dialogs", "SelectFile");
        var oneOfImplicit = FindOneOfImplicit();
        var nullableCtor = FindNullableCtor();
        var valueTupleCtor = FindValueTupleCtor();
        var valueTupleType = valueTupleCtor.DeclaringType;
        var listGetCount = m.Import(typeof(List<string>).GetProperty("Count").GetGetMethod());
        var listGetItem = m.Import(typeof(List<string>).GetProperty("Item").GetGetMethod());
        var runInThread = m.Types.SelectMany(x => x.Methods)
                            .FirstOrDefault(x => x.Name == "RunInThread" && x.MethodSig.Params.Count == 1);
        if (runInThread == null) throw new Exception("RunInThread not found");

        il.Clear();
        body.ExceptionHandlers.Clear();
        body.Variables.Clear();
        var vClosure = new Local(closureType.ToTypeSig());
        var vList = new Local(selectFile.MethodSig.RetType);
        body.Variables.Add(vClosure);
        body.Variables.Add(vList);
        body.InitLocals = true;

        var lblRet = Instruction.Create(OpCodes.Ret);

        var filter = new List<Instruction>();
        if (noFilter)
        {
            var nullableType = selectFile.MethodSig.Params[3];
            var vDefault = new Local(nullableType);
            body.Variables.Add(vDefault);
            filter.Add(Instruction.Create(OpCodes.Ldloca, vDefault));
            filter.Add(Instruction.Create(OpCodes.Initobj, nullableType.ToTypeDefOrRef()));
            filter.Add(Instruction.Create(OpCodes.Ldloc, vDefault));
        }
        else
        {
        filter.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        filter.Add(Instruction.Create(OpCodes.Newarr, valueTupleType));
        filter.Add(Instruction.Create(OpCodes.Dup));
        filter.Add(Instruction.Create(OpCodes.Ldc_I4_0));
        filter.Add(Instruction.Create(OpCodes.Ldc_I4_3));
        filter.Add(Instruction.Create(OpCodes.Newarr, m.CorLibTypes.String.ToTypeDefOrRef()));
        string[] exts = { "rar", "zip", "mrpack" };
        for (int i = 0; i < exts.Length; i++)
        {
            filter.Add(Instruction.Create(OpCodes.Dup));
            filter.Add(Instruction.Create(OpCodes.Ldc_I4, i));
            filter.Add(Instruction.Create(OpCodes.Ldstr, exts[i]));
            filter.Add(Instruction.Create(OpCodes.Stelem_Ref));
        }
        filter.Add(Instruction.Create(OpCodes.Ldstr, "整合包文件"));
        filter.Add(Instruction.Create(OpCodes.Newobj, valueTupleCtor));
        filter.Add(Instruction.Create(OpCodes.Stelem, valueTupleType));
        filter.Add(Instruction.Create(OpCodes.Call, oneOfImplicit));
        filter.Add(Instruction.Create(OpCodes.Newobj, nullableCtor));
        }

        var sel = new List<Instruction>();
        sel.Add(Instruction.Create(OpCodes.Newobj, closureCtor));
        sel.Add(Instruction.Create(OpCodes.Stloc, vClosure));
        sel.Add(Instruction.Create(OpCodes.Ldstr, "选择整合包压缩文件"));
        sel.Add(Instruction.Create(OpCodes.Ldc_I4_0));
        sel.Add(Instruction.Create(OpCodes.Ldnull));
        sel.AddRange(filter);
        sel.Add(Instruction.Create(OpCodes.Call, selectFile));
        sel.Add(Instruction.Create(OpCodes.Stloc, vList));

        sel.Add(Instruction.Create(OpCodes.Ldloc, vList));
        sel.Add(Instruction.Create(OpCodes.Callvirt, listGetCount));
        sel.Add(Instruction.Create(OpCodes.Brfalse, lblRet));

        sel.Add(Instruction.Create(OpCodes.Ldloc, vClosure));
        sel.Add(Instruction.Create(OpCodes.Ldloc, vList));
        sel.Add(Instruction.Create(OpCodes.Ldc_I4_0));
        sel.Add(Instruction.Create(OpCodes.Callvirt, listGetItem));
        sel.Add(Instruction.Create(OpCodes.Stfld, fileField));
        sel.Add(Instruction.Create(OpCodes.Ldloc, vClosure));
        sel.Add(Instruction.Create(OpCodes.Ldftn, lambda));
        sel.Add(Instruction.Create(OpCodes.Newobj,
            m.Import(typeof(Action).GetConstructor(new[] { typeof(object), typeof(IntPtr) }))));
        sel.Add(Instruction.Create(OpCodes.Call, runInThread));
        sel.Add(lblRet);

        foreach (var ins in sel) il.Add(ins);

        body.MaxStack = 8;
        body.KeepOldMaxStack = keepStack;
        body.UpdateInstructionOffsets();
        Console.WriteLine("entry   : instrs=" + il.Count);
    }

    // Restore the version-item click behaviour on the resource detail page.
    // Newer builds keep Install_Click and its proxy lambda in the binary but no
    // longer wire them up, so clicking a version only saves the archive. This
    // re-adds the original branch: for modpacks the item click installs, and
    // the icon button saves; for every other resource type nothing changes.
    static void PatchDetailClick()
    {
        var page = m.Find("PCL.PageDownloadResourceDetail", false) as TypeDef;
        if (page == null) throw new Exception("detail page type not found");
        var md = page.Methods.FirstOrDefault(x =>
            x.Name == "InitializeStackResourceVersions" && x.MethodSig.Params.Count == 1);
        if (md == null || md.Body == null) throw new Exception("version list method not found");
        var body = md.Body;
        var il = body.Instructions;

        var typeField = page.Fields.FirstOrDefault(f => f.Name == "TargetResourceType");
        if (typeField == null) throw new Exception("target type field not found");

        // The method already reads the field once before the version loop.
        int reads = 0;
        foreach (var ins in il)
            if (ins.OpCode == OpCodes.Ldfld && ins.Operand == typeField) reads++;
        if (reads > 1)
        {
            Console.WriteLine("detail : already applied");
            return;
        }

        var install = page.Methods.FirstOrDefault(x =>
            x.Name == "Install_Click" && x.MethodSig.Params.Count == 2);
        if (install == null) throw new Exception("install handler not found");

        // The proxy is the compiler-generated lambda that calls Install_Click.
        MethodDef proxy = null;
        foreach (var cand in page.Methods)
        {
            if (cand.Body == null) continue;
            foreach (var ins in cand.Body.Instructions)
            {
                var mr = ins.Operand as IMethod;
                if (ins.OpCode == OpCodes.Call && mr != null &&
                    mr.Name == "Install_Click" &&
                    mr.DeclaringType.FullName == page.FullName)
                { proxy = cand; break; }
            }
            if (proxy != null) break;
        }
        if (proxy == null) throw new Exception("install proxy not found");

        // Locate the block that creates one version row:
        //   ldarg.1 / callvirt get_Children / ldloc.s v / ldarg.0
        //   ldftn Save_Click / newobj MyListItem/ClickEventHandler / ldnull
        //   ldloc.1 / callvirt ToListItem / callvirt Add / pop
        int at = -1;
        for (int k = 0; k + 11 < il.Count; k++)
        {
            if (il[k].OpCode != OpCodes.Ldarg_1) continue;
            if (!IsCall(il[k + 1], "get_Children")) continue;
            if (il[k + 2].OpCode != OpCodes.Ldloc_S) continue;
            if (il[k + 3].OpCode != OpCodes.Ldarg_0) continue;
            if (il[k + 4].OpCode != OpCodes.Ldftn || !IsMethod(il[k + 4], "Save_Click")) continue;
            if (il[k + 5].OpCode != OpCodes.Newobj) continue;
            if (il[k + 6].OpCode != OpCodes.Ldnull) continue;
            if (il[k + 7].OpCode != OpCodes.Ldloc_1) continue;
            if (!IsCall(il[k + 8], "ToListItem")) continue;
            if (!IsCall(il[k + 9], "Add")) continue;
            if (il[k + 10].OpCode != OpCodes.Pop) continue;
            at = k;
            break;
        }
        if (at < 0) throw new Exception("version row block not found");

        var getChildren = (IMethod)il[at + 1].Operand;
        var vVersion = (Local)il[at + 2].Operand;
        var saveClick = (IMethod)il[at + 4].Operand;
        var itemCtor = (IMethod)il[at + 5].Operand;
        var toListItem = (IMethod)il[at + 8].Operand;
        var addItem = (IMethod)il[at + 9].Operand;
        var normalTarget = il[at];
        var loopNext = il[at + 11];

        var iconType = m.Find("PCL.MyIconButton/ClickEventHandler", false) as TypeDef;
        if (iconType == null) throw new Exception("icon handler type not found");
        var iconCtor = iconType.FindMethod(".ctor");
        if (iconCtor == null) throw new Exception("icon handler ctor not found");

        var seq = new List<Instruction>();
        seq.Add(Instruction.Create(OpCodes.Ldarg_0));
        seq.Add(Instruction.Create(OpCodes.Ldfld, typeField));
        seq.Add(Instruction.Create(OpCodes.Ldc_I4_2));
        seq.Add(Instruction.Create(OpCodes.Bne_Un, normalTarget));
        seq.Add(Instruction.Create(OpCodes.Ldarg_1));
        seq.Add(Instruction.Create(OpCodes.Callvirt, getChildren));
        seq.Add(Instruction.Create(OpCodes.Ldloc_S, vVersion));
        seq.Add(Instruction.Create(OpCodes.Ldarg_0));
        seq.Add(Instruction.Create(OpCodes.Ldftn, proxy));
        seq.Add(Instruction.Create(OpCodes.Newobj, itemCtor));
        seq.Add(Instruction.Create(OpCodes.Ldarg_0));
        seq.Add(Instruction.Create(OpCodes.Ldftn, saveClick));
        seq.Add(Instruction.Create(OpCodes.Newobj, iconCtor));
        seq.Add(Instruction.Create(OpCodes.Ldloc_1));
        seq.Add(Instruction.Create(OpCodes.Callvirt, toListItem));
        seq.Add(Instruction.Create(OpCodes.Callvirt, addItem));
        seq.Add(Instruction.Create(OpCodes.Pop));
        seq.Add(Instruction.Create(OpCodes.Br, loopNext));

        for (int k = 0; k < seq.Count; k++) il.Insert(at + k, seq[k]);

        WidenBranches(body);
        body.MaxStack = (ushort)Math.Max((int)body.MaxStack, 6);
        body.UpdateInstructionOffsets();
        Console.WriteLine("detail : instrs=" + body.Instructions.Count);
    }

    static bool IsCall(Instruction ins, string name)
    {
        if (ins.OpCode != OpCodes.Callvirt && ins.OpCode != OpCodes.Call) return false;
        return IsMethod(ins, name);
    }

    static bool IsMethod(Instruction ins, string name)
    {
        var mr = ins.Operand as IMethod;
        return mr != null && mr.Name == name;
    }

    // Short branches cannot reach past the inserted block, so use long forms.
    static void WidenBranches(CilBody body)
    {
        foreach (var ins in body.Instructions)
        {
            switch (ins.OpCode.Code)
            {
                case Code.Br_S: ins.OpCode = OpCodes.Br; break;
                case Code.Brfalse_S: ins.OpCode = OpCodes.Brfalse; break;
                case Code.Brtrue_S: ins.OpCode = OpCodes.Brtrue; break;
                case Code.Beq_S: ins.OpCode = OpCodes.Beq; break;
                case Code.Bne_Un_S: ins.OpCode = OpCodes.Bne_Un; break;
                case Code.Bge_S: ins.OpCode = OpCodes.Bge; break;
                case Code.Bge_Un_S: ins.OpCode = OpCodes.Bge_Un; break;
                case Code.Bgt_S: ins.OpCode = OpCodes.Bgt; break;
                case Code.Bgt_Un_S: ins.OpCode = OpCodes.Bgt_Un; break;
                case Code.Ble_S: ins.OpCode = OpCodes.Ble; break;
                case Code.Ble_Un_S: ins.OpCode = OpCodes.Ble_Un; break;
                case Code.Blt_S: ins.OpCode = OpCodes.Blt; break;
                case Code.Blt_Un_S: ins.OpCode = OpCodes.Blt_Un; break;
                case Code.Leave_S: ins.OpCode = OpCodes.Leave; break;
            }
        }
    }

    static MemberRef FindMemberRef(string type, string name)
    {
        var r = m.GetMemberRefs().FirstOrDefault(x =>
            x.DeclaringType != null && x.DeclaringType.FullName == type && x.Name == name);
        if (r == null) throw new Exception("member ref not found: " + type + "::" + name);
        return r;
    }

    static MemberRef FindOneOfImplicit()
    {
        foreach (var x in m.GetMemberRefs())
        {
            if (x.Name != "op_Implicit") continue;
            if (!x.DeclaringType.FullName.StartsWith("MeloongCore.OneOf`2<System.Collections.Generic.IEnumerable`1<System.ValueTuple")) continue;
            if (x.MethodSig == null || x.MethodSig.Params.Count != 1) continue;
            var gp = x.MethodSig.Params[0] as GenericSig;
            if (gp != null && gp.Number == 0) return x;
        }
        throw new Exception("implicit conversion not found");
    }

    static MemberRef FindNullableCtor()
    {
        var r = m.GetMemberRefs().FirstOrDefault(x =>
            x.Name == ".ctor" && x.DeclaringType.FullName.StartsWith("System.Nullable`1") &&
            x.DeclaringType.FullName.Contains("OneOf") && x.MethodSig.Params.Count == 1);
        if (r == null) throw new Exception("nullable ctor not found");
        return r;
    }

    static MemberRef FindValueTupleCtor()
    {
        var r = m.GetMemberRefs().FirstOrDefault(x =>
            x.Name == ".ctor" &&
            x.DeclaringType.FullName == "System.ValueTuple`2<System.String[],System.String>" &&
            x.MethodSig.Params.Count == 2);
        if (r == null) throw new Exception("value tuple ctor not found");
        return r;
    }
}
