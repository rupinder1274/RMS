// Script to migrate all AssignedSchedule.dailyHours keys to 'D-MMM' format
const mongoose = require('mongoose');
const AssignedSchedule = require('../models/AssignedSchedule');

mongoose.connect('mongodb://127.0.0.1:27017/hrms-app', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

function formatDateKey(dateStr) {
  if (/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
    const d = new Date(dateStr);
    const day = d.getDate();
    const monthName = d.toLocaleString('default', { month: 'short' });
    return `${day}-${monthName}`;
  }
  return dateStr;
}

async function migrate() {
  const schedules = await AssignedSchedule.find({});
  let updatedCount = 0;
  for (const sched of schedules) {
    if (!sched.dailyHours) continue;
    let needsUpdate = false;
    const newDailyHours = {};
    for (const key of Object.keys(sched.dailyHours)) {
      const newKey = formatDateKey(key);
      if (newKey !== key) needsUpdate = true;
      newDailyHours[newKey] = sched.dailyHours[key];
    }
    if (needsUpdate) {
      sched.dailyHours = newDailyHours;
      await sched.save();
      updatedCount++;
      console.log(`Updated schedule ${sched._id}`);
    }
  }
  console.log(`Migration complete. Updated ${updatedCount} schedules.`);
  mongoose.disconnect();
}

migrate();
