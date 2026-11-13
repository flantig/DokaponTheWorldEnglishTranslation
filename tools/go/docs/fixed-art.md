# Versioned fixed artwork

The canonical record is [fixed-instances.json](../recipes/artwork/fixed-instances.json).
It joins an existing-schema texture profile to approved readable pixels, the exact
verification mask, retained source art and independent native/RGBA expectations.
The profile owns source/image pins, the selector and rectangle coordinates. Keep
those facts there; the record references its exact bytes.

The first instance, `allmap_1.logo-a.v1`, preserves an already approved horizontal
DOKAPON THE WORLD logo A. The earlier brand2 generator is superseded only for this
named fixed override. This does not implement arbitrary restoration, lettering,
Telea, exemplar, radial or material generation. Original14/84/410history remains;
this instance grants no milestone, family or historical retirement credit.

The candidate batch adds thirteen named source-cache versions through that same
importer. Ten retain historical permission masks. `win_w` and `win_fw` instead
bind different extracted-cache inputs to the identical approved complete images.
Their old masks each exclude 2,839 changed pixels, so the old edit contract is
explicitly not replayed. Their separate exact netdelta masks are reconstruction
verification bounds, not prior or renewed editing permission. No pristine ISO
lineage is inferred from an extracted-cache identity.

Shared bundle identities, approval authority, source artwork and maintenance
contracts are stored once in the instance table. The original `allmap_1` pilot
record remains unchanged. The retained source logo is shared by the two map
versions and title. Other approved flattened images remain distinct source data.
Casino's mask is the historical mask union the approval script's explicit
`[174,246,296,128]` repair rectangle; tests check that exact union.

Race's historical native bundle member differs from its approved PNG in 18,723
pixels, including 91 alpha bytes. That mismatch remains historical evidence.
A separately reviewed invocation of the historical encoder produced the exact
complete approved image; its independently verified bytes form a distinct reference
fixture. The old native bundle is unchanged. Race's fine generator mask excludes
6,532 approved changes, so its new fixed reconstruction also uses an exact netdelta
verification bound. All changes remain inside the approval script's three coarse
rectangles. The fourteen records (including the original pilot) passed the reviewed
Go replay. Acceptance and verification limits are canonical in
[fixed-art-proof.json](../evidence/fixed-art-proof.json#accepted_batch_v4).
This does not complete `raster_rendering.06`.

Use the existing Go tools. From the toolkit directory, build an executable into an
owned output directory. The Golden command creates isolated native outputs.
The accepted batch used two fresh package reviews and a separate execution release;
later native applications need their own concrete package and release.
The texture command computes a read-only preview:

```sh
go test -run '^TestPilotHistoricalGoldenBytes$' -count=1 .
/path/to/registry-patch --source /path/to/pristine-allmap_1.txd --texture-profile profiles/textures/fixed-art/allmap_1-logo-a-v1.json
```

The second command is read-only. Compare its complete native/RGBA identities to
the record, rather than treating successful palette import as equivalence. The
Golden check compares every native byte to the existing approved bundle member,
all four decoded channels against the original and exact binary mask, and preserves
the CLUT and other nonpixel bytes. It also checks source/image/geometry refusals.
No Python runtime or special artwork executor is required.

For the reviewed Golden invocation, bind `TMPDIR` to a fresh private parent and
freeze the precompiled test executable, working directory, all input hashes and
exact arguments. Each fixed-art instance creates its own mode0700 directory.
After complete output, refusal and source-preservation checks, cleanup verifies
that directory's identity. Failure or timeout retains the failing directory for
quarantine; successful instances remove only their own directory. Verbose test
output records each completed instance and its measured native digest. The rest
of the existing Golden test retains its normal temporary-fixture behavior.

The static PNG importer enforces the profile's coarse rectangles, not the holes in
the exact verification mask. Tests demonstrate that a changed in-mask image can
import yet fail the old native target, and that an edit in a mask hole can pass the
coarse rectangle yet fail independent exact-mask containment. A pinned image binds
its approved wording; there is no OCR or runtime textual-content validator.

The canonical `maintenance_witnesses` table freezes canvas-relative points and
RGBA values from independent source/approved images. Thirteen versions have a
fine-mask hole inside a declared rectangle. `op_p` fills its entire eleven-rectangle
union, so no such hole exists: complete mask/union equality is required instead,
and a one-pixel edit outside that union must refuse without publishing an output.
Guard edits use a different opaque color sampled from the pinned source palette.
All fourteen pure native/RGBA/mask/maintenance checks run before any fixed-art CLI
replay begins. This boundary does not preflight unrelated later Golden groups.

Before a real standalone import, complete two fresh independent reviews of the
concrete source/profile/approved-image/mask/predicted-result package. Freeze the
exact executable, profile, source and image bytes plus the complete apply argv
across read-only preview and application. The independently approved native SHA
is an external verification gate. `writeNewFile` checks the computed artifact's
size/digest/readback and exclusive output, which is a separate self-integrity
contract. Do not describe it as an independently approved-target runtime guard.

Only then use the same executable and inputs with `--apply --output` into a new
owned standalone TXD. Check full output bytes, decoded RGBA, exact-mask containment,
unchanged nonpixel data and original input identity afterward. This is not an ISO
write or approval for later placement.

For an intentional image or wording edit, retain the shared source/layer provenance,
create a new named version and obtain fresh art approval with independently frozen
native/RGBA/mask expectations. A wider change needs a reviewed new mask and bounds.
Updating only hashes does not establish equivalence or preserve the old approval.
Keep the old version and unsupported editable-generator requirements in history.
