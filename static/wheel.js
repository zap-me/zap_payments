function wheelSectors(sectorCount, winCount) {
    let sectors = [];
    let c1 = "#aaaaaa";
    let c2 = "#cccccc";
    let cw1 = "#ffaaaa";
    let cw2 = "#aaffaa";
    let r = Math.floor(sectorCount / winCount);
    for (var i = 0; i < sectorCount; i++) {
        if (i % r == 0 && winCount > 0) {
            let color = winCount % 2 == 0 ? cw1 : cw2;
            sectors.push({ color: color, label: "WIN", win: true });
            winCount--;
        } else {
            let color = i % 2 == 0 ? c1 : c2;
            sectors.push({ color: color, label: "", win: false });
        }
    }
    return sectors;
}

function wheelInit(sectors, delayMs, targetWinningSector, finishedCallback) {
    const rand = (m, M) => Math.random() * (M - m) + m;
    const tot = sectors.length;
    const EL_spin = document.querySelector("#spin");
    const ctx = document.querySelector("#wheel").getContext('2d');
    const dia = ctx.canvas.width;
    const rad = dia / 2;
    const PI = Math.PI;
    const TAU = 2 * PI;
    const arc = TAU / sectors.length;

    const friction = 0.991; // 0.995=soft, 0.99=mid, 0.98=hard
    let angVel = 0; // Angular velocity
    let ang = 0; // Angle in radians

    const getIndex = () => Math.floor(tot - ang / TAU * tot) % tot;
    const getAngle = (sectorIndex) => -arc * (sectorIndex + 0.5);

    function drawSector(sector, i) {
        const ang = arc * i;
        ctx.save();
        // COLOR
        ctx.beginPath();
        ctx.fillStyle = sector.color;
        ctx.moveTo(rad, rad);
        ctx.arc(rad, rad, rad, ang, ang + arc);
        ctx.lineTo(rad, rad);
        ctx.fill();
        // TEXT
        ctx.translate(rad, rad);
        ctx.rotate(ang + arc / 2);
        ctx.textAlign = "right";
        ctx.fillStyle = "#fff";
        ctx.font = "bold 30px sans-serif";
        ctx.fillText(sector.label, rad - 10, 10);
        //
        ctx.restore();
    };

    function rotate() {
        const sector = sectors[getIndex()];
        ctx.canvas.style.transform = `rotate(${ang - PI / 2}rad)`;
        EL_spin.textContent = sector.label;
        EL_spin.style.background = sector.color;
    }

    function frame() {
        if (!angVel) return;
        angVel *= friction; // Decrement velocity by friction
        if (angVel < 0.0002) angVel = 0; // Bring to stop
        ang += angVel; // Update angle
        ang %= TAU; // Normalize angle
        rotate();
    }

    function engine() {
        frame();
        if (angVel > 0)
            requestAnimationFrame(engine)
        else
            finishedCallback();
    }

    function calcAngVelocity() {
        // find sector index
        let sectorIndex = 0;
        let count = rand(sectors.length + 1, sectors.length * 10);
        for (var i = 0; i < count; i++) {
            if (targetWinningSector) {
                if (sectors[i % sectors.length].win) {
                    sectorIndex = i % sectors.length;
                }
            }
            else {
                if (!sectors[i % sectors.length].win) {
                    sectorIndex = i % sectors.length;
                }
            }
        }
        console.log('target sector index ' + sectorIndex);
        // find target angle
        let targetAng = getAngle(sectorIndex) + 3 * TAU;
        let travelledAng = 0;
        let currentAngVel = 0.0000000000000001;
        while (travelledAng < targetAng) {
            travelledAng += currentAngVel;
            currentAngVel *= (1 / friction);
        }
        console.log('target angle: ' + targetAng);
        console.log('travalled angle: ' + travelledAng);
        console.log('calculated angular velocity: ' + currentAngVel);
        return currentAngVel;
    }

    sectors.forEach(drawSector);
    rotate(); // Initial rotation
    angVel = calcAngVelocity();
    window.setTimeout(() => {
        engine(); // Start engine
    }, delayMs);
}