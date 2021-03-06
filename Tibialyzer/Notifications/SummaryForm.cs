﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Tibialyzer {
    public partial class SummaryForm : NotificationForm {
        private int ImageWidth = 200;
        private int ImageHeight = 25;
        private object updateLock = new object();

        public SummaryForm() {
            InitializeComponent();
        }

        public void RenderText(Graphics gr, string text, int x, Color fillColor, Color textColor) {
            gr.InterpolationMode = InterpolationMode.High;
            gr.SmoothingMode = SmoothingMode.HighQuality;
            gr.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;
            gr.CompositingQuality = CompositingQuality.HighQuality;
            GraphicsPath p = new GraphicsPath();
            p.AddString(
               text,
                FontFamily.GenericMonospace,
                (int)FontStyle.Bold,
                gr.DpiY * 10 / 72,
                new Point(x, 4),
                new StringFormat());
            if (x < 0) {
                x = (int)(Math.Abs(x) - p.GetBounds().Width - 10);
                p = new GraphicsPath();
                p.AddString(
                   text,
                    FontFamily.GenericMonospace,
                    (int)FontStyle.Bold,
                    gr.DpiY * 10 / 72,
                    new Point(x, 4),
                    new StringFormat());
            }
            if (fillColor != Color.Empty) {
                using (Brush brush = new SolidBrush(fillColor)) {
                    gr.FillRectangle(brush, new RectangleF(p.GetBounds().X - 8, 0, p.GetBounds().Width + 16, ImageHeight - 1));
                }
                gr.DrawRectangle(Pens.Black, new Rectangle((int)p.GetBounds().X - 8, 0, (int)p.GetBounds().Width + 16, ImageHeight - 1));
            }
            using (Pen pen = new Pen(Color.Black, 2)) {
                gr.DrawPath(pen, p);
            }
            using (SolidBrush brush = new SolidBrush(textColor)) {
                gr.FillPath(brush, p);
                p.GetBounds();
            }
        }

        public void RenderImageResized(Graphics gr, Image image, Rectangle targetRectangle) {
            int x = targetRectangle.X, y = targetRectangle.Y;
            int width = targetRectangle.Width, height = targetRectangle.Height;
            if (image.Width > image.Height) {
                height = (int)Math.Floor(height * ((double)image.Height / image.Width));
                y += (width - height) / 2;
            } else if (image.Height > image.Width) {
                width = (int)Math.Floor(width * ((double)image.Width / image.Height));
                x += (height - width) / 2;
            }
            lock(image) {
                gr.DrawImage(image, new Rectangle(x, y, width, height), new Rectangle(0, 0, image.Width, image.Height), GraphicsUnit.Pixel);
            }
        }

        public Image CreatureBox(Creature creature, int amount = 0) {
            Bitmap bitmap = new Bitmap(ImageWidth, ImageHeight);
            using (Graphics gr = Graphics.FromImage(bitmap)) {
                Color backColor = StyleManager.GetElementColor(creature.GetStrength());
                using (Brush brush = new SolidBrush(backColor)) {
                    gr.FillRectangle(brush, new Rectangle(0, 0, bitmap.Width, bitmap.Height));
                }
                gr.DrawRectangle(Pens.Black, new Rectangle(0, 0, bitmap.Width - 1, bitmap.Height - 1));
                RenderImageResized(gr, StyleManager.GetImage("item_background.png"), new Rectangle(1, 1, ImageHeight - 2, ImageHeight - 2));
                RenderImageResized(gr, creature.GetImage(), new Rectangle(1, 1, ImageHeight - 2, ImageHeight - 2));
                RenderText(gr, creature.displayname.ToTitle(), ImageHeight + 2, Color.Empty, StyleManager.NotificationTextColor);
                if (amount > 0) {
                    RenderText(gr, amount.ToString(), -ImageWidth, Color.FromArgb(backColor.R / 2, backColor.G / 2, backColor.B / 2), StyleManager.NotificationTextColor);
                }
            }
            return bitmap;
        }

        public Image ItemBox(Item item, int amount = 0) {
            Bitmap bitmap = new Bitmap(ImageWidth, ImageHeight);
            using (Graphics gr = Graphics.FromImage(bitmap)) {
                using (Brush brush = new SolidBrush(StyleManager.MainFormButtonColor)) {
                    gr.FillRectangle(brush, new Rectangle(0, 0, bitmap.Width, bitmap.Height));
                }
                gr.DrawRectangle(Pens.Black, new Rectangle(0, 0, bitmap.Width - 1, bitmap.Height - 1));
                RenderImageResized(gr, StyleManager.GetImage("item_background.png"), new Rectangle(1, 1, ImageHeight - 2, ImageHeight - 2));
                RenderImageResized(gr, (amount > 1 || item.stackable) ? LootDropForm.GetStackImage(item.GetImage(), amount > 0 ? amount : 1, item) : item.GetImage(), new Rectangle(1, 1, ImageHeight - 2, ImageHeight - 2));
                RenderText(gr, item.displayname.ToTitle(), ImageHeight + 2, Color.Empty, StyleManager.NotificationTextColor);
                if (amount > 0) {
                    RenderText(gr, amount.ToString(), -ImageWidth, Color.FromArgb(StyleManager.MainFormButtonColor.R / 2, StyleManager.MainFormButtonColor.G / 2, StyleManager.MainFormButtonColor.B / 2), StyleManager.NotificationTextColor);
                }
            }
            return bitmap;
        }

        public Image SummaryBox(string header, string value, Color textColor) {
            Bitmap bitmap = new Bitmap(ImageWidth, ImageHeight);
            using (Graphics gr = Graphics.FromImage(bitmap)) {
                using (SolidBrush brush = new SolidBrush(StyleManager.MainFormButtonColor)) {
                    gr.FillRectangle(brush, new RectangleF(0, 0, ImageWidth, ImageHeight));
                }
                gr.DrawRectangle(Pens.Black, new Rectangle(0, 0, bitmap.Width - 1, bitmap.Height - 1));
                RenderText(gr, header, 0, Color.Empty, StyleManager.NotificationTextColor);
                RenderText(gr, value, -ImageWidth, Color.FromArgb(StyleManager.MainFormButtonColor.R / 2, StyleManager.MainFormButtonColor.G / 2, StyleManager.MainFormButtonColor.B / 2), textColor);
            }
            return bitmap;
        }

        public Image RecentDropsBox(Creature creature, List<Tuple<Item, int>> items) {
            Bitmap bitmap = new Bitmap(ImageWidth, ImageHeight);
            using (Graphics gr = Graphics.FromImage(bitmap)) {
                using (Brush brush = new SolidBrush(StyleManager.MainFormButtonColor)) {
                    gr.FillRectangle(brush, new Rectangle(0, 0, bitmap.Width, bitmap.Height));
                }
                gr.DrawRectangle(Pens.Black, new Rectangle(0, 0, bitmap.Width - 1, bitmap.Height - 1));
                RenderImageResized(gr, StyleManager.GetImage("item_background.png"), new Rectangle(1, 1, ImageHeight - 2, ImageHeight - 2));
                RenderImageResized(gr, creature.GetImage(), new Rectangle(1, 1, ImageHeight - 1, ImageHeight - 1));
                int count = 0;
                foreach (Tuple<Item, int> item in items) {
                    Rectangle region = new Rectangle(8 + (ImageHeight - 1) * ++count, 1, ImageHeight - 2, ImageHeight - 2);
                    RenderImageResized(gr, StyleManager.GetImage("item_background.png"), region);
                    RenderImageResized(gr, (item.Item1.stackable || item.Item2 > 1) ? LootDropForm.DrawCountOnItem(item.Item1, item.Item2) : item.Item1.GetImage(), region);
                }
            }
            return bitmap;
        }

        private void CreateHeaderLabel(string title, int x, ref int y, List<Control> controls) {
            Label label = new Label();
            label.Text = title;
            label.Location = new Point(x, y);
            label.Size = new Size(ImageWidth, 15);
            label.BackColor = Color.Transparent;
            label.ForeColor = StyleManager.NotificationTextColor;
            label.Font = StyleManager.MainFormLabelFontSmall;
            this.Controls.Add(label);
            controls.Add(label);
            y += 15;
        }

        private void CreateSummaryLabel(string title, string value, int x, ref int y, Color color, List<Control> controls) {
            Image image = SummaryBox(title, value, color);
            PictureBox box = new PictureBox();
            box.Size = image.Size;
            box.BackColor = Color.Transparent;
            box.Location = new Point(x, y);
            box.Image = image;
            this.Controls.Add(box);
            controls.Add(box);
            y += box.Height;
        }

        private void CreateItemBox(Item item, int count, int x, ref int y, List<Control> controls) {
            Image image = ItemBox(item, count);
            PictureBox box = new PictureBox();
            box.Size = image.Size;
            box.BackColor = Color.Transparent;
            box.Location = new Point(x, y);
            box.Image = image;
            box.Name = "item" + Constants.CommandSymbol + item.title;
            box.Click += CommandClick;
            this.Controls.Add(box);
            controls.Add(box);
            y += box.Height;
        }

        private void CreateCreatureBox(Creature creature, int count, int x, ref int y, List<Control> controls) {
            Image image = CreatureBox(creature, count);
            PictureBox box = new PictureBox();
            box.Size = image.Size;
            box.BackColor = Color.Transparent;
            box.Location = new Point(x, y);
            box.Image = image;
            box.Name = "creature" + Constants.CommandSymbol + creature.title;
            box.Click += CommandClick;
            this.Controls.Add(box);
            controls.Add(box);
            y += box.Height;
        }
        private void CreateCreatureDropsBox(Creature creature, List<Tuple<Item, int>> items, string message, int x, ref int y, List<Control> controls) {
            Image image = RecentDropsBox(creature, items);
            PictureBox box = new PictureBox();
            box.Size = image.Size;
            box.BackColor = Color.Transparent;
            box.Location = new Point(x, y);
            box.Image = image;
            box.Name = "creature" + Constants.CommandSymbol + creature.title;
            box.Click += CommandClick;
            this.Controls.Add(box);
            controls.Add(box);
            // copy button
            PictureBox copyButton = new PictureBox();
            copyButton.Size = new Size(box.Size.Height - 4, box.Size.Height - 4);
            copyButton.BackColor = StyleManager.MainFormButtonColor;
            copyButton.Location = new Point(box.Location.X + box.Size.Width - box.Size.Height + 2, y + 2);
            copyButton.Click += CopyLootText;
            copyButton.Name = message;
            copyButton.Image = StyleManager.GetImage("copyicon.png");
            copyButton.SizeMode = PictureBoxSizeMode.Zoom;
            this.Controls.Add(copyButton);
            controls.Add(copyButton);
            copyButton.BringToFront();

            y += box.Height;
        }

        private void CopyLootText(object sender, EventArgs e) {
            Clipboard.SetText((sender as Control).Name);
        }

        private void CreateItemList(List<Tuple<Item, int>> items, int x, ref int y, List<Control> controls) {
            Image image = new Bitmap(ImageWidth, ImageHeight);
            using(Graphics gr = Graphics.FromImage(image)) {
                int counter = 0;
                foreach(Tuple<Item, int> item in items) {
                    Rectangle region = new Rectangle(x + (counter++) * (ImageHeight + 1), 0, ImageHeight - 1, ImageHeight - 1);
                    RenderImageResized(gr, StyleManager.GetImage("item_background.png"), region);
                    RenderImageResized(gr, (item.Item1.stackable || item.Item2 > 1) ? LootDropForm.DrawCountOnItem(item.Item1, item.Item2) : item.Item1.GetImage(), region);
                }
            }
            PictureBox box = new PictureBox();
            box.Size = image.Size;
            box.BackColor = Color.Transparent;
            box.Location = new Point(x, y);
            box.Image = image;
            this.Controls.Add(box);
            controls.Add(box);
            y += box.Height;
        }

        private int x = 5;
        private List<Control> summaryControls = new List<Control>();
        private List<Control> lootControls = new List<Control>();
        private List<Control> damageControls = new List<Control>();
        private List<Control> usedItemsControls = new List<Control>();
        public override void LoadForm() {
            this.SuspendForm();
            
            Label label;
            label = new Label();
            label.Text = "Summary";
            label.Location = new Point(x, 0);
            label.Size = new Size(ImageWidth, 30);
            label.BackColor = Color.Transparent;
            label.ForeColor = StyleManager.NotificationTextColor;
            label.Font = StyleManager.MainFormLabelFontSmall;
            label.TextAlign = ContentAlignment.MiddleCenter;
            this.Controls.Add(label);
            
            this.NotificationInitialize();

            this.NotificationFinalize();
            this.ResumeForm();

            this.RefreshForm();
        }

        public void ClearControlList(List<Control> list, out int minheight, out int maxheight) {
            minheight = int.MaxValue;
            maxheight = int.MinValue;
            foreach (Control c in list) {
                if (c.Location.Y < minheight) {
                    minheight = c.Location.Y;
                }
                if (c.Location.Y + c.Height > maxheight) {
                    maxheight = c.Location.Y + c.Height;
                }
                this.Controls.Remove(c);
                c.Dispose();
            }
            list.Clear();
        }

        private long totalValue = 0;
        public void UpdateSummaryForm() {
            int minheight, maxheight;
            ClearControlList(summaryControls, out minheight, out maxheight);
            int y = maxheight < 0 ? 30 : minheight;

            CreateSummaryLabel("Loot", totalValue.ToString(), x, ref y, StyleManager.ItemGoldColor, summaryControls);
            CreateSummaryLabel("Exp", HuntManager.activeHunt.totalExp.ToString(), x, ref y, StyleManager.NotificationTextColor, summaryControls);
            CreateSummaryLabel("Time", LootDropForm.TimeToString((long)HuntManager.activeHunt.totalTime), x, ref y, StyleManager.NotificationTextColor, summaryControls);
        }

        public void UpdateLoot() {
            lock (updateLock) {
                this.SuspendForm();
                this.UpdateLootForm();
                this.UpdateSummaryForm();
                this.ResumeForm();
            }
        }

        public void UpdateDamage() {
            try {
                if (this.IsDisposed) return;
                this.Invoke((MethodInvoker)delegate {
                    lock (updateLock) {
                        this.SuspendForm();
                        this.UpdateDamageForm();
                        this.ResumeForm();
                    }
                });
            } catch {

            }
        }

        public void UpdateWaste() {
            try {
                if (this.IsDisposed) return;
                this.Invoke((MethodInvoker)delegate {
                    lock (updateLock) {
                        this.SuspendForm();
                        this.UpdateWasteForm();
                        this.UpdateSummaryForm();
                        this.ResumeForm();
                    }
                });
            } catch {

            }
        }

        public void UpdateLootForm() {
            Hunt hunt = HuntManager.activeHunt;
            int minheight, maxheight;
            ClearControlList(lootControls, out minheight, out maxheight);

            int counter;
            int y = minheight;
            if (maxheight < 0) {
                y = 30;
                foreach (Control c in summaryControls) {
                    y = Math.Max(c.Location.Y + c.Height, y);
                }
            }
            var loot = LootDropForm.GenerateLootInformation(hunt, "", null);
            totalValue = 0;
            foreach (Tuple<Item, int> tpl in loot.Item2) {
                totalValue += tpl.Item1.GetMaxValue() * tpl.Item2;
            }

            int maxDrops = SettingsManager.getSettingInt("SummaryMaxItemDrops");
            if (maxDrops < 0) maxDrops = 5;
            if (maxDrops > 0) {
                CreateHeaderLabel("Item Drops", x, ref y, lootControls);
                counter = 0;
                int width = 0;
                var items = new List<Tuple<Item, int>>();
                foreach (Tuple<Item, int> tpl in loot.Item2) {
                    int amount = tpl.Item2;
                    while(amount > 0) {
                        int count = Math.Min(100, amount);
                        amount -= count;
                        items.Add(new Tuple<Item, int>(tpl.Item1, count));
                        width += ImageHeight + 2;
                        if (width > ImageWidth - ImageHeight) {
                            CreateItemList(items, x, ref y, lootControls);
                            items.Clear();
                            width = 0;
                            if (++counter >= maxDrops) break;
                        }
                    }
                }
                if (items.Count > 0) {
                    CreateItemList(items, x, ref y, lootControls);
                    items.Clear();
                }
            }
            int maxCreatures = SettingsManager.getSettingInt("SummaryMaxCreatures");
            if (maxCreatures < 0) maxCreatures = 5;
            if (maxCreatures > 0) {
                CreateHeaderLabel("Creature Kills", x, ref y, lootControls);
                counter = 0;
                foreach (Creature cr in loot.Item1.Keys.OrderByDescending(o => loot.Item1[o] * (1 + o.experience)).ToList<Creature>()) {
                    CreateCreatureBox(cr, loot.Item1[cr], x, ref y, lootControls);
                    if (++counter >= maxCreatures) break;
                }
            }
            int maxRecentDrops = SettingsManager.getSettingInt("SummaryMaxRecentDrops");
            if (maxRecentDrops < 0) maxRecentDrops = 5;
            if (maxRecentDrops > 0) {
                CreateHeaderLabel("Recent Drops", x, ref y, lootControls);
                var recentDrops = ScanningManager.GetRecentDrops(maxRecentDrops);
                foreach (var drops in recentDrops) {
                    CreateCreatureDropsBox(drops.Item1, drops.Item2, drops.Item3, x, ref y, lootControls);
                }
            }
            UpdateDamageForm();
        }

        public void UpdateDamageForm() {
            Hunt hunt = HuntManager.activeHunt;

            int minheight, maxheight;
            ClearControlList(damageControls, out minheight, out maxheight);
            int y = minheight;

            y = 30;
            foreach (Control c in lootControls.Count > 0 ? lootControls : summaryControls) {
                y = Math.Max(c.Location.Y + c.Height, y);
            }

            int maxDamage = SettingsManager.getSettingInt("SummaryMaxDamagePlayers");
            if (maxDamage < 0) maxDamage = 5;
            if (maxDamage > 0 && ScanningManager.lastResults != null) {
                CreateHeaderLabel("Damage Dealt", x, ref y, damageControls);
                var dps = ScanningManager.lastResults.damagePerSecond;
                var damageDealt = DamageChart.GenerateDamageInformation(dps, "");
                for (int i = 0; i < damageDealt.Count; i++) {
                    damageDealt[i].color = Constants.ChartColors[i % Constants.ChartColors.Count];
                }
                int counter = 0;
                foreach (DamageObject obj in damageDealt) {
                    CreateSummaryLabel(obj.name, String.Format("{0:0.0}%", obj.percentage), x, ref y, obj.color, damageControls);
                    if (++counter >= maxDamage) {
                        break;
                    }
                }
            }
            UpdateWasteForm();
        }

        public void UpdateWasteForm() {
            Hunt hunt = HuntManager.activeHunt;

            int minheight, maxheight;
            ClearControlList(usedItemsControls, out minheight, out maxheight);

            int y = 30;
            foreach (Control c in damageControls.Count > 0 ? damageControls : (lootControls.Count > 0 ? lootControls : summaryControls)) {
                y = Math.Max(c.Location.Y + c.Height, y);
            }

            int maxUsedItems = SettingsManager.getSettingInt("SummaryMaxUsedItems");
            if (maxUsedItems < 0) maxUsedItems = 5;
            if (maxUsedItems > 0) {
                int counter = 0;
                CreateHeaderLabel("Used Items", x, ref y, usedItemsControls);
                int width = 0;
                var items = new List<Tuple<Item, int>>();
                foreach (Tuple<Item, int> tpl in HuntManager.GetUsedItems(hunt)) {
                    int amount = tpl.Item2;
                    while (amount > 0) {
                        int count = Math.Min(100, amount);
                        amount -= count;
                        items.Add(new Tuple<Item, int>(tpl.Item1, count));
                        width += ImageHeight + 2;
                        if (width > ImageWidth - ImageHeight) {
                            CreateItemList(items, x, ref y, usedItemsControls);
                            items.Clear();
                            width = 0;
                            if (++counter >= maxUsedItems) break;
                        }
                    }
                }
                if (items.Count > 0) {
                    CreateItemList(items, x, ref y, usedItemsControls);
                    items.Clear();
                }
            }
            if (y != maxheight) {
                this.Size = new Size(ImageWidth + 10, y + 5);
            }
        }

        private void CommandClick(object sender, EventArgs e) {
            CommandManager.ExecuteCommand((sender as Control).Name);
        }

        public override string FormName() {
            return "SummaryForm";
        }

        public override int MinWidth() {
            return 210;
        }

        public override int MaxWidth() {
            return 410;
        }

        public override int WidthInterval() {
            return 50;
        }

        public override void RefreshForm() {
            this.SuspendForm();
            this.Size = new Size(GetWidth(), this.Size.Height);
            ImageWidth = this.Size.Width - 10;

            UpdateSummaryForm();
            UpdateLootForm();
            UpdateDamageForm();
            UpdateWasteForm();
            //update the summary form again because the loot value is computed in UpdateLootForm()
            //and UpdateLootForm() has to be called after UpdateLootForm() because it needs the controls to be added to compute its base y position
            UpdateSummaryForm();

            this.ResumeForm();
        }
    }
}
