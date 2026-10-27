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
    // 2.99.0.0 and 2.99.0.1 phrase the notice slightly differently.
    static readonly string[] ComplianceMessages =
    {
        "为遵守相关法律法规，PCL 暂时不再提供 MC 下载功能，非常抱歉 qwq……",
        "为遵守相关法律法规，PCL 不再提供 MC 下载功能，非常抱歉 qwq……",
    };

    const string HiddenSetting = "UiHiddenPageDownload";

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
        PatchDownloadPage();
        PatchResourcePageType();
        PatchInstanceModDownload();
        PatchEmptyDownloadButton();
        PatchLaunchButton();
        PatchFolderInstallItem();
        PatchFullUpdate();

        m.Write(outPath);
        Console.WriteLine("written: " + outPath);
    }

    static TypeDef FindType(string fullName)
    {
        var td = m.Find(fullName, false) as TypeDef;
        if (td == null) throw new Exception("type not found: " + fullName);
        return td;
    }

    static MethodDef FindMethod(TypeDef td, string name, int pc)
    {
        var md = td.Methods.FirstOrDefault(x =>
            x.Name == name && x.MethodSig.Params.Count == pc);
        if (md == null || md.Body == null)
            throw new Exception("method not found: " + td.Name + "::" + name + "/" + pc);
        return md;
    }

    static void InsertRange(IList<Instruction> il, int at, List<Instruction> seq)
    {
        for (int k = 0; k < seq.Count; k++) il.Insert(at + k, seq[k]);
    }

    static void Step(string name, string detail)
    {
        Console.WriteLine("  {0,-24} {1}", name, detail);
    }

    static bool HasString(MethodDef md, string value)
    {
        return md.Body.Instructions.Any(x => x.OpCode == OpCodes.Ldstr && (string)x.Operand == value);
    }

    static void PatchDispatch()
    {
        var md = M("ModpackInstall", 3);
        var body = md.Body;
        var il = body.Instructions;

        int idx = -1;
        for (int i = 0; i + 2 < il.Count; i++)
        {
            if (il[i].OpCode == OpCodes.Ldstr && ComplianceMessages.Contains((string)il[i].Operand) &&
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
        Step("modpack dispatch", "applied, " + il.Count + " instrs");
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
        Step("modpack entry", "applied, " + il.Count + " instrs");
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
            Step("detail click", "already applied");
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
        Step("detail click", "applied, " + body.Instructions.Count + " instrs");
    }

    // 2.99.0.1 selects the mods category on the download page, collapses the
    // modpack entry and hides the resource section. Restore the 2.99.0.0
    // constructor tail so the page starts on its default category again.
    static void PatchDownloadPage()
    {
        var page = FindType("PCL.PageDownloadLeft");
        var ctor = FindMethod(page, ".ctor", 0);
        var body = ctor.Body;
        var il = body.Instructions;

        int start = -1;
        for (int i = 0; i + 1 < il.Count; i++)
            if (IsCall(il[i], "InitializeComponent")) { start = i + 1; break; }
        if (start < 0) throw new Exception("download page ctor: InitializeComponent not found");

        int ret = -1;
        for (int i = start; i < il.Count; i++)
            if (il[i].OpCode == OpCodes.Ret) { ret = i; break; }
        if (ret < 0) throw new Exception("download page ctor: ret not found");

        if (ret == start)
        {
            Step("download page", "already applied");
            return;
        }

        for (int i = ret - 1; i >= start; i--) il.RemoveAt(i);
        body.UpdateInstructionOffsets();
        Step("download page", "applied, " + il.Count + " instrs");
    }

    // 2.99.0.1 always collapses the modpack search button. Restore the
    // condition: it is collapsed only while the page type is modpack.
    static void PatchResourcePageType()
    {
        var page = FindType("PCL.PageResource");
        var md = FindMethod(page, "set_PageType", 1);
        var body = md.Body;
        var il = body.Instructions;

        for (int i = 0; i + 4 < il.Count; i++)
        {
            if (il[i].OpCode != OpCodes.Ldarg_1 || il[i + 1].OpCode != OpCodes.Ldc_I4_2) continue;

            if ((il[i + 2].OpCode == OpCodes.Beq || il[i + 2].OpCode == OpCodes.Beq_S) &&
                (il[i + 4].OpCode == OpCodes.Br || il[i + 4].OpCode == OpCodes.Br_S) &&
                (il[i + 3].OpCode == OpCodes.Ldc_I4_0 || il[i + 3].OpCode == OpCodes.Ldc_I4_2))
            {
                Step("resource page", "already applied");
                return;
            }
            if (il[i + 2].OpCode != OpCodes.Pop || il[i + 3].OpCode != OpCodes.Pop ||
                il[i + 4].OpCode != OpCodes.Ldc_I4_2) continue;
            if (i + 5 >= il.Count || !IsCall(il[i + 5], "set_Visibility")) continue;

            var zeroValue = il[i + 4];
            var call = il[i + 5];
            il[i + 2].OpCode = OpCodes.Beq;
            il[i + 2].Operand = zeroValue;
            il[i + 3].OpCode = OpCodes.Ldc_I4_2;
            il[i + 3].Operand = null;
            zeroValue.OpCode = OpCodes.Ldc_I4_0;
            zeroValue.Operand = null;
            il.Insert(i + 4, Instruction.Create(OpCodes.Br, call));
            WidenBranches(body);
            body.MaxStack = (ushort)Math.Max((int)body.MaxStack, 4);
            body.UpdateInstructionOffsets();
            Step("resource page", "applied, " + il.Count + " instrs");
            return;
        }
        throw new Exception("resource page type: layout not found");
    }

    // 2.99.0.1 always collapses the download button on the disabled-mods page.
    // Restore the 2.99.0.0 visibility computation.
    static void PatchInstanceModDownload()
    {
        var page = FindType("PCL.PageInstanceModDisabled");
        var md = FindMethod(page, "BtnDownload_Loaded", 0);
        var il = md.Body.Instructions;
        if (HasString(md, HiddenSetting))
        {
            Step("disabled mod download", "already applied");
            return;
        }
        if (il.Count < 2 || il[0].OpCode != OpCodes.Ldc_I4_2 || il[1].OpCode != OpCodes.Stloc_0)
            throw new Exception("download: mod button layout not found");

        var get = FindHiddenSettingGet();
        var force = FindHiddenForceShow();
        var frm = FindType("PCL.ModMain").FindField("FrmSelectRight");
        var showHidden = FindType("PCL.PageSelectRight").FindField("ShowHidden");
        if (frm == null || showHidden == null)
            throw new Exception("download: hidden state members not found");

        var zero = Instruction.Create(OpCodes.Ldc_I4_0);
        var two = Instruction.Create(OpCodes.Ldc_I4_2);
        var probe = Instruction.Create(OpCodes.Ldsfld, frm);
        var test = Instruction.Create(OpCodes.Brtrue, two);
        var store = Instruction.Create(OpCodes.Stloc_0);
        var seq = new List<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, HiddenSetting),
            Instruction.Create(OpCodes.Ldnull),
            Instruction.Create(OpCodes.Call, get),
            Instruction.Create(OpCodes.Brfalse, probe),
            Instruction.Create(OpCodes.Call, force),
            Instruction.Create(OpCodes.Brfalse, two),
            probe,
            Instruction.Create(OpCodes.Brfalse, zero),
            Instruction.Create(OpCodes.Ldsfld, frm),
            Instruction.Create(OpCodes.Ldfld, showHidden),
            Instruction.Create(OpCodes.Br, test),
            zero,
            test,
            Instruction.Create(OpCodes.Ldc_I4_0),
            Instruction.Create(OpCodes.Br, store),
            two,
            store,
        };
        InsertRange(il, 0, seq);
        il.RemoveAt(seq.Count);
        il.RemoveAt(seq.Count);
        md.Body.MaxStack = (ushort)Math.Max((int)md.Body.MaxStack, 4);
        md.Body.UpdateInstructionOffsets();
        Step("disabled mod download", "applied, " + il.Count + " instrs");
    }

    // 2.99.0.1 always collapses the download button on the empty version list.
    // Restore the 2.99.0.0 conditional visibility.
    static void PatchEmptyDownloadButton()
    {
        var page = FindType("PCL.PageSelectRight");
        var md = FindMethod(page, "McInstanceListUI", 1);
        var il = md.Body.Instructions;
        if (HasString(md, HiddenSetting))
        {
            Step("empty download", "already applied");
            return;
        }

        int at = -1;
        for (int i = 0; i + 2 < il.Count; i++)
            if (IsCall(il[i], "get_BtnEmptyDownload")) at = i;
        if (at < 0) throw new Exception("download: empty button call not found");
        if (il[at + 1].OpCode != OpCodes.Ldc_I4_2 || !IsCall(il[at + 2], "set_Visibility"))
            throw new Exception("download: empty button layout not found");

        var get = FindHiddenSettingGet();
        var force = FindHiddenForceShow();
        var call = il[at + 2];
        var zero = Instruction.Create(OpCodes.Ldc_I4_0);
        var two = Instruction.Create(OpCodes.Ldc_I4_2);
        var seq = new List<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, HiddenSetting),
            Instruction.Create(OpCodes.Ldnull),
            Instruction.Create(OpCodes.Call, get),
            Instruction.Create(OpCodes.Brfalse, zero),
            Instruction.Create(OpCodes.Call, force),
            Instruction.Create(OpCodes.Brfalse, two),
            zero,
            Instruction.Create(OpCodes.Br, call),
            two,
        };
        InsertRange(il, at + 1, seq);
        il.RemoveAt(at + 1 + seq.Count);
        WidenBranches(md.Body);
        md.Body.MaxStack = (ushort)Math.Max((int)md.Body.MaxStack, 4);
        md.Body.UpdateInstructionOffsets();
        Step("empty download", "applied, " + il.Count + " instrs");
    }

    // 2.99.0.1 pins the "no instance selected" launch button state to 1.
    // Restore the 2.99.0.0 conditional that may also use state 2.
    static void PatchLaunchButton()
    {
        var page = FindType("PCL.PageLaunchLeft");
        var md = FindMethod(page, "RefreshButtonsUI", 0);
        var il = md.Body.Instructions;
        if (HasString(md, HiddenSetting))
        {
            Step("launch button", "already applied");
            return;
        }

        int at = -1;
        for (int i = 0; i + 5 < il.Count; i++)
        {
            if (!IsCall(il[i], "get_McInstanceSelected")) continue;
            if (il[i + 1].OpCode != OpCodes.Brtrue && il[i + 1].OpCode != OpCodes.Brtrue_S) continue;
            if (il[i + 2].OpCode != OpCodes.Ldc_I4_1) continue;
            if (il[i + 3].OpCode != OpCodes.Stloc_0) continue;
            if (il[i + 4].OpCode != OpCodes.Br && il[i + 4].OpCode != OpCodes.Br_S) continue;
            if (il[i + 5].OpCode != OpCodes.Ldc_I4_3) continue;
            at = i + 2;
            break;
        }
        if (at < 0) throw new Exception("download: launch state layout not found");

        var end = il[at + 5];
        var get = FindHiddenSettingGet();
        var force = FindHiddenForceShow();
        var two = Instruction.Create(OpCodes.Ldc_I4_2);
        var seq = new List<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, HiddenSetting),
            Instruction.Create(OpCodes.Ldnull),
            Instruction.Create(OpCodes.Call, get),
            Instruction.Create(OpCodes.Brfalse, two),
            Instruction.Create(OpCodes.Call, force),
            Instruction.Create(OpCodes.Brtrue, two),
            Instruction.Create(OpCodes.Ldc_I4_1),
            Instruction.Create(OpCodes.Stloc_0),
            Instruction.Create(OpCodes.Br, end),
            two,
            Instruction.Create(OpCodes.Stloc_0),
            Instruction.Create(OpCodes.Br, end),
        };
        InsertRange(il, at, seq);
        for (int k = 0; k < 3; k++) il.RemoveAt(at + seq.Count);
        WidenBranches(md.Body);
        md.Body.MaxStack = (ushort)Math.Max((int)md.Body.MaxStack, 4);
        md.Body.UpdateInstructionOffsets();
        Step("launch button", "applied, " + il.Count + " instrs");
    }

    // 2.99.0.1 still builds the "install modpack" item for the selected folder
    // but never appends it to the list. Restore the 2.99.0.0 insertion.
    static void PatchFolderInstallItem()
    {
        var page = FindType("PCL.PageSelectLeft");
        var md = FindMethod(page, "McFolderListUI", 0);
        var il = md.Body.Instructions;

        int wiring = -1;
        for (int i = 0; i + 1 < il.Count; i++)
        {
            if (il[i].OpCode != OpCodes.Ldloc_1 || il[i + 1].OpCode != OpCodes.Ldsfld) continue;
            var field = il[i + 1].Operand as IField;
            if (field == null || field.Name != "$IR4-8") continue;
            wiring = i;
            break;
        }
        if (wiring < 0) throw new Exception("download: folder install item not found");
        if (wiring > 0 && il[wiring - 1].OpCode == OpCodes.Pop)
        {
            Step("folder install", "already applied");
            return;
        }

        IField frmLeft = null;
        IMethod panList = null, children = null, add = null;
        foreach (var ins in il)
        {
            var field = ins.Operand as IField;
            if (ins.OpCode == OpCodes.Ldsfld && frmLeft == null && field != null &&
                field.Name == "FrmSelectLeft")
                frmLeft = field;
            var mm = ins.Operand as IMethod;
            if (ins.OpCode != OpCodes.Callvirt || mm == null) continue;
            if (panList == null && mm.Name == "get_PanList") panList = mm;
            if (children == null && mm.Name == "get_Children") children = mm;
            if (add == null && mm.Name == "Add" && mm.MethodSig.Params.Count == 1 &&
                mm.DeclaringType.FullName.Contains("UIElementCollection"))
                add = mm;
        }
        if (frmLeft == null || panList == null || children == null || add == null)
            throw new Exception("download: folder list members not found");

        var seq = new List<Instruction>
        {
            Instruction.Create(OpCodes.Ldsfld, frmLeft),
            Instruction.Create(OpCodes.Callvirt, panList),
            Instruction.Create(OpCodes.Callvirt, children),
            Instruction.Create(OpCodes.Ldloc_1),
            Instruction.Create(OpCodes.Callvirt, add),
            Instruction.Create(OpCodes.Pop),
        };
        InsertRange(il, wiring, seq);
        WidenBranches(md.Body);
        md.Body.MaxStack = (ushort)Math.Max((int)md.Body.MaxStack, 4);
        md.Body.UpdateInstructionOffsets();
        Step("folder install", "applied, " + il.Count + " instrs");
    }

    // 2.99.x builds delta-patch URLs from the MD5/SHA1 of the running exe.
    // A patched exe no longer matches any published patch, so the request ends
    // up as HTTP 404. Skip the PatchUrls branch and use the full package list.
    static void PatchFullUpdate()
    {
        MethodDef found = null;
        int at = -1;
        bool applied = false;
        Instruction target = null;

        foreach (var type in m.GetTypes())
        {
            foreach (var cand in type.Methods)
            {
                if (cand.Body == null) continue;
                if (!HasString(cand, "PatchUrls") || !HasString(cand, "DownloadUrls")) continue;
                var il = cand.Body.Instructions;
                for (int i = 0; i + 3 < il.Count; i++)
                {
                    if (il[i].OpCode != OpCodes.Ldstr || (string)il[i].Operand != "PatchUrls") continue;
                    if (!IsCall(il[i + 1], "ContainsKey")) continue;

                    if (il[i + 2].OpCode == OpCodes.Brfalse || il[i + 2].OpCode == OpCodes.Brfalse_S)
                    {
                        target = il[i + 2].Operand as Instruction;
                        applied = false;
                    }
                    else if (il[i + 2].OpCode == OpCodes.Pop && il[i + 3].OpCode == OpCodes.Br)
                    {
                        target = il[i + 3].Operand as Instruction;
                        applied = true;
                    }
                    else continue;

                    if (found != null) throw new Exception("update source: ambiguous layout");
                    found = cand;
                    at = i + 2;
                }
            }
        }
        if (found == null) throw new Exception("update source: layout not found");

        var body = found.Body;
        var il2 = body.Instructions;
        int t = -1;
        for (int i = 0; i < il2.Count; i++)
            if (ReferenceEquals(il2[i], target)) { t = i; break; }
        if (t < 0) throw new Exception("update source: branch target not found");

        bool fullPackage = false;
        for (int i = t; i < il2.Count && i <= t + 4; i++)
            if (il2[i].OpCode == OpCodes.Ldstr && (string)il2[i].Operand == "DownloadUrls")
                fullPackage = true;
        if (!fullPackage) throw new Exception("update source: unexpected branch target");

        if (applied)
        {
            Step("update source", "already applied");
            return;
        }

        // Keep the stack balanced: the conditional branch consumes the
        // ContainsKey result, so replace it with pop + unconditional jump over
        // the PatchUrls block.
        il2[at].OpCode = OpCodes.Pop;
        il2[at].Operand = null;
        il2.Insert(at + 1, Instruction.Create(OpCodes.Br, target));
        body.UpdateInstructionOffsets();
        Step("update source", "full package");
    }

    static MethodDef FindHiddenStateMethod()
    {
        return FindMethod(FindType("PCL.PageSelectRight"), "BtnEmptyDownload_Loaded", 0);
    }

    static IMethod FindHiddenSettingGet()
    {
        foreach (var ins in FindHiddenStateMethod().Body.Instructions)
        {
            var mm = ins.Operand as IMethod;
            if (ins.OpCode == OpCodes.Call && mm != null && mm.Name == "Get" &&
                mm.DeclaringType.FullName == "PCL.Settings")
                return mm;
        }
        throw new Exception("hidden setting accessor not found");
    }

    static IMethod FindHiddenForceShow()
    {
        foreach (var ins in FindHiddenStateMethod().Body.Instructions)
        {
            var mm = ins.Operand as IMethod;
            if (ins.OpCode == OpCodes.Call && mm != null && mm.Name == "get_HiddenForceShow")
                return mm;
        }
        throw new Exception("hidden force-show accessor not found");
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
