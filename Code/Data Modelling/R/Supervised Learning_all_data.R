##################### Libraries #####################
library(randomForest)
library(ranger)
library(plyr)
library(gbm)
library(caret)
library(pROC)
library(tidyverse)
library(plotROC)
library(e1701)

#Parallelization
library(parallel)
library(doParallel)


##################### Reading & Splitting Data #####################
setwd('/Users/babraham/Google Drive/Grad_School/Fall_2017/Cyber_Research/Anomaly-based-Intrusion-Detection-System/Code/Data Modelling/R')
dir = '/Users/babraham/Google Drive/Grad_School/Cyber_Research/Anomaly-based-Intrusion-Detection-System/Code/Data Modelling/R'
all_data <- read.csv(paste(dir,'merged_data_final.csv',sep="/"), header=T) #reading in the data

for(c in colnames(all_data)){
  print(paste(c,length(which(is.na(all_data[,c]))),sep='-'))
}


#get rid of corrupted trace sample
all_data <- all_data[which(all_data$File != "traces_141_1.log.csv"),]
#get rid of index
all_data <- all_data[,-c(1)]

drop_flags <- c("t","T","Q","q","H","h")
all_data <- all_data[,!(colnames(all_data) %in% drop_flags)]

colnames(all_data)[20:29] <- paste("src", colnames(all_data)[20:29], sep = "_")
colnames(all_data)[30:39] <- paste("dest", colnames(all_data)[30:39], sep = "_")

all_data$Malicious <- as.factor(ifelse(all_data$Malicious ==1, "Yes", "No"))
set.seed(134)

train_index <- sample(1:nrow(all_data), 16500, replace= FALSE)

caret_data <- all_data[train_index,-c(2:6,32:35)]
caret_test <- all_data[-train_index,-c(2:6,32:35)]

caret_data$Malicious <- as.factor(caret_data$Malicious)
levels(caret_data$Malicious) <- c("Benign", "Malicious")
caret_test$Malicious <- as.factor(caret_test$Malicious)
levels(caret_test$Malicious) <- c("Benign", "Malicious")

##################### Data Exploration #####################
library(ggplot2)
#Mean interval Distribution
test1 <- all_data[all_data$mean_intvl<1000,]

plot1 <- ggplot(data = test1,aes(x= Malicious, y=mean_intvl, fill = Malicious)) + geom_boxplot()+
        scale_fill_manual(values=c("green", "red"))+
        theme(aspect.ratio = 3/6,axis.text=element_text(size=12, face = "bold",color = "grey19"),
        axis.title=element_text(size=20,face="bold",color = "grey19"))

ggplot(data = test2,aes(x= Malicious, y= mean_intvl, fill = Malicious)) + geom_boxplot()+
  scale_fill_manual(values=c("green", "red"))+
  theme(axis.text=element_text(size=12, face = "bold",color = "grey19"),
        axis.title=element_text(size=20,face="bold",color = "grey19"))

boxplot(caret_data$Malicious, caret_data$mean_intvl)


#Mean Source Packets
test2 <- all_data[all_data$mean_src_pkts<100,]

ggplot(data = test2,aes(x= Malicious, y= mean_src_pkts, fill = Malicious)) + geom_boxplot()+
  scale_fill_manual(values=c("green", "red"))+
  theme(axis.text=element_text(size=12, face = "bold",color = "grey19"),
        axis.title=element_text(size=20,face="bold",color = "grey19"))

#Mean Dest Packets
ggplot(data = test4,aes(x= Malicious, y= delta, fill = Malicious)) + geom_boxplot()+
  scale_fill_manual(values=c("green", "red"))+
  theme(axis.text=element_text(size=12, face = "bold",color = "grey19"),
        axis.title=element_text(size=20,face="bold",color = "grey19"))
m <- "mean_src_pkts"

#Mean Duration
test3 <- all_data[all_data$mean_duration<500,]

plot2 <- ggplot(data = test3,aes(x= Malicious, y= mean_duration, fill = Malicious)) + geom_boxplot()+
  scale_fill_manual(values=c("green", "red"))+
  theme(aspect.ratio = 3/6,axis.text=element_text(size=12, face = "bold",color = "grey19"),
        axis.title=element_text(size=20,face="bold",color = "grey19"))
  #stat_summary(fun.y=mean, colour="black", geom="point", shape=18, size=3)+
  #geom_text(data = test3, aes(label = Malicious, y = mean_duration))


#Mean flowct
quantile(all_data$flowct, na.rm=TRUE)
testfc <- all_data[all_data$flowct<36,]

plotfc <- ggplot(data = testfc,aes(x= Malicious, y= flowct, fill = Malicious)) + geom_boxplot()+
  scale_fill_manual(values=c("green", "red"))+
  theme(aspect.ratio = 3/6,axis.text=element_text(size=12, face = "bold",color = "grey19"),
        axis.title=element_text(size=20,face="bold",color = "grey19"))+
  stat_summary(fun.y=mean, colour="black", geom="point", shape=18, size=3)+
  geom_text(data = test3, aes(label = Malicious, y = mean_intvl))

grid.arrange(plot1, plot2, ncol=2)

metrics = c("dest_t", "src_H", "src_T", "dest_r", "mean_src_pkts",  "src_R")
plots <- list()
idx = 1
for(m in metrics){
  print(m)
  pdata = caret_data[which(caret_data[,c(m)] < quantile(caret_data[,m], probs=c(.9))),]
  plots[[idx]] = ggplot(data = pdata,aes_string(x= "Malicious", y= m, fill = "Malicious")) + geom_boxplot()+
    scale_fill_manual(values=c("green", "red"))+
    theme(aspect.ratio = 3/6,axis.text=element_text(size=12, face = "bold",color = "grey19"),
          axis.title=element_text(size=20,face="bold",color = "grey19"))
  idx = idx + 1
}
grid.arrange(plots[[1]], plots[[2]], plots[[3]], plots[[4]], plots[[5]], plots[[6]], ncol=2)

##################### Caret Implementation of Logistic Regression ##################### 

#Start clusters
cluster <- makeCluster(detectCores())
registerDoParallel(cluster)

#Tuning length for all caret models
tun_len <- 5

set.seed(234)
control <- trainControl(method="cv", 
                        summaryFunction=twoClassSummary, classProbs=T,
                        savePredictions = T,allowParallel = TRUE
                        )


lr <- train(as.factor(Malicious) ~., data = caret_data, method = "glm",
            family = "binomial",
            trControl=control,
            preProcess = c("BoxCox"),
            metric = "ROC",
            tuneLength = tun_len)
test_pred_lr <- predict(lr, newdata=caret_test[,-1])

#Since caret train didn't converge, try training with glm where we can set max iterations
lr2 <- glm(as.factor(Malicious) ~ ., data=caret_data, family="binomial", 
           control = glm.control(maxit = 1000))

#Make data frame for logistic regression predictions that mimics caret df structure
#create columns
train_pred_lr2 <- predict.glm(lr2, newdata=caret_data[,-1], type="response")
test_pred_lr2 <- predict.glm(lr2, newdata=caret_test[,-1], type="response")
rowIndex <- attributes(test_pred_lr2)
rowIndex <- as.integer(rowIndex$names)
Yes <- as.numeric(test_pred_lr2)
pred <- sapply(Yes, function(x){ifelse(x>.5, "Yes", "No")})
pred <- factor(pred, levels = c("No", "Yes"))
obs <- as.factor(caret_test[,1])

#build dataframe
lr.df <- data.frame(Yes)
lr.df$pred <- pred
lr.df$obs <- obs
lr.df$rowIndex <- rowIndex

#Confusion Matrix
confusionMatrix(lr.df$pred, caret_test[,1])

#ROC
selectedIndices_lr <- rep(TRUE, length(lr.df$pred))
l <- ggplot(lr.df, aes(m = Yes,d=factor(obs, levels = c("Yes", "No")))) + 
  geom_roc(n.cuts=0) + 
  coord_equal() +
  style_roc()

l + annotate("text", y=0.25, x=0.75,label=paste("LR AUC =", round((calc_auc(h))$AUC, 4)))

calc_auc(l)
##################### LR Results #####################
# Confusion Matrix and Statistics
# 
# Reference
# Prediction   No  Yes
# No  1787   28
# Yes  413 1646
# 
# Accuracy : 0.8862         
# 95% CI : (0.8757, 0.896)
# No Information Rate : 0.5679         
# P-Value [Acc > NIR] : < 2.2e-16      
# 
# Kappa : 0.7743         
# Mcnemar's Test P-Value : < 2.2e-16      
# 
# Sensitivity : 0.8123         
# Specificity : 0.9833         
# Pos Pred Value : 0.9846         
# Neg Pred Value : 0.7994         
# Prevalence : 0.5679         
# Detection Rate : 0.4613         
# Detection Prevalence : 0.4685         
# Balanced Accuracy : 0.8978         

##################### Caret Implementation of Radial SVM ##################### 
library(caret)
#Start clusters
cluster <- makeCluster(detectCores())
registerDoParallel(cluster)

set.seed(4)
control <- trainControl(method="cv", 
                        summaryFunction=twoClassSummary, classProbs=T,
                        savePredictions = T,allowParallel = TRUE)


svm_Radial <- train(as.factor(Malicious) ~., data = caret_data, method = "svmRadial",
                    trControl=control,
                    preProcess = c("center"),
                    metric = "ROC",
                    tuneLength = tun_len, 
                    na_action=na.exclude)

print(svm_Radial)

# Select a parameter setting
selectedIndices_svm <- svm_Radial$pred$C == 128

g <- ggplot(svm_Radial$pred[selectedIndices_svm, ], aes(m = Yes,d=factor(obs, levels = c("Yes", "No")))) + 
  geom_roc(n.cuts=0) + 
  coord_equal() +
  style_roc()

g + annotate("text", y=0.25, x=0.75,label=paste("AUC =", round((calc_auc(g))$AUC, 4)))


#test
test_pred_svmr <- predict(svm_Radial, newdata = caret_test[,-1])
svm_cfn_matrix = confusionMatrix(test_pred_svmr, as.factor(caret_test[,1]))
svm_cfn_matrix$byClass[['F1']]
##################### SVM-R Results #####################
# "Confusion Matrix and Statistics
# Reference
# Prediction   No  Yes
# No  1854  248
# Yes  346 1426
# 
# Accuracy : 0.8467          
# 95% CI : (0.8349, 0.8579)
# No Information Rate : 0.5679          
# P-Value [Acc > NIR] : < 2.2e-16       
# 
# Kappa : 0.6898          
# Mcnemar's Test P-Value : 6.893e-05       
# 
# Sensitivity : 0.8427          
# Specificity : 0.8519          
# Pos Pred Value : 0.8820          
# Neg Pred Value : 0.8047          
# Prevalence : 0.5679          
# Detection Rate : 0.4786          
# Detection Prevalence : 0.5426          
# Balanced Accuracy : 0.8473
##################### Caret Implementation of Random Forest ##################### 

#Start clusters
cluster <- makeCluster(detectCores())
registerDoParallel(cluster)

set.seed(234)
control <- trainControl(method="cv", 
                        summaryFunction=twoClassSummary, classProbs=T,
                        savePredictions = T,allowParallel = TRUE)


rf <- train(as.factor(Malicious) ~., data = caret_data, method = "rf",
                    trControl=control,
                    preProcess = c("center"),
                    metric = "ROC",
                    tuneLength = tun_len)

print(rf)

# Select a parameter setting
selectedIndices_rf <- rf$pred$mtry == 2

rf$pred$mtry

h <- ggplot(rf$pred[selectedIndices_rf, ], aes(m = Yes,d=factor(obs, levels = c("Yes", "No")))) + 
  geom_roc(n.cuts=0) + 
  coord_equal() +
  style_roc()

h + annotate("text", y=0.25, x=0.75,label=paste("RF AUC =", round((calc_auc(h))$AUC, 4)))

calc_auc(h)
#test
test_pred_rf <- predict(rf, newdata = caret_test[,-1])
rf_cm <- confusionMatrix(test_pred_rf, as.factor(caret_test[,1]))

##################### Random Forest Results #####################
# Confusion Matrix and Statistics
# 
# Reference
# Prediction   No  Yes
# No  2186    9
# Yes   14 1665
# 
# Accuracy : 0.9941          
# 95% CI : (0.9911, 0.9962)
# No Information Rate : 0.5679          
# P-Value [Acc > NIR] : <2e-16          
# 
# Kappa : 0.9879          
# Mcnemar's Test P-Value : 0.4042          
# 
# Sensitivity : 0.9936          
# Specificity : 0.9946          
# Pos Pred Value : 0.9959          
# Neg Pred Value : 0.9917          
# Prevalence : 0.5679          
# Detection Rate : 0.5643          
# Detection Prevalence : 0.5666          
# Balanced Accuracy : 0.9941          

##################### Caret Implementation of Naive Bayes ##################### 

#Start clusters
cluster <- makeCluster(detectCores())
registerDoParallel(cluster)

set.seed(234)
control <- trainControl(method="cv", 
                        summaryFunction=twoClassSummary, classProbs=T,
                        savePredictions = T,allowParallel = TRUE)


nb <- train(as.factor(Malicious) ~., data = caret_data, method = "nb",
            trControl=control,
            preProcess = c("center"),
            metric = "ROC",
            tuneLength = tun_len)

print(nb)

# Select a parameter setting
selectedIndices_nb <- which(nb$pred$usekernel == "TRUE" & nb$pred$fL == 0 & nb$pred$adjust == 1)
selectedIndices_nb <- which(nb$pred$fL == 0)


k <- ggplot(nb$pred[selectedIndices_nb, ], aes(m = Yes,d=factor(obs, levels = c("Yes", "No")))) + 
  geom_roc(n.cuts=0) + 
  coord_equal() +
  style_roc()

k + annotate("text", y=0.25, x=0.75,label=paste("AUC =", round((calc_auc(k))$AUC, 4)))

test_pred_nb <- predict(nb, newdata = caret_test[,-1])
nb_cm <-  confusionMatrix(test_pred_nb, as.factor(caret_test[,1]))
nb_cm$byClass[['F1']]
##################### Naive Bayes Results ##################### 

# Confusion Matrix and Statistics
# 
# Reference
# Prediction   No  Yes
# No    83   25
# Yes 2117 1649
# 
# Accuracy : 0.4471          
# 95% CI : (0.4313, 0.4629)
# No Information Rate : 0.5679          
# P-Value [Acc > NIR] : 1               
# 
# Kappa : 0.0198          
# Mcnemar's Test P-Value : <2e-16          
# 
# Sensitivity : 0.03773         
# Specificity : 0.98507         
# Pos Pred Value : 0.76852         
# Neg Pred Value : 0.43787         
# Prevalence : 0.56789         
# Detection Rate : 0.02142         
# Detection Prevalence : 0.02788         
# Balanced Accuracy : 0.51140         
# 
# 'Positive' Class : No  
##################### Caret Implementation of Neural Net ##################### 

#Start clusters
cluster <- makeCluster(detectCores())
registerDoParallel(cluster)

set.seed(456)
control <- trainControl(method="cv", 
                        summaryFunction=twoClassSummary, classProbs=T,
                        savePredictions = T,allowParallel = TRUE)

num_vars <- ncol(caret_data) -1
mlp_grid = expand.grid(layer1 = num_vars,
                       layer2 = 10, 
                       layer3 = 2)


mlp_grid2 = expand.grid(layer1 = c(10,num_vars),
                       layer2 = c(50,10,5), 
                       layer3 = c(5,2,0)
                       )

##Params##

#10, 5,0 -> .933, .67, .95
#10,10,0 -> .933, .77, .70
#10,50,0 -> .934, .82, .70
#26,10,0 -> .933, .75, .77
#26,50,0 -> .934, .83, .64

nn <- train(as.factor(Malicious) ~., data = caret_data, method = "mlpML",
            trControl=control,
            preProcess = c("range"),
            metric = "ROC",
            tuneGrid=mlp_grid)

print(nn)

# Select a parameter setting
layer1 <- c(26,10)
layer2 <- c(50,10, 5)

plots <- c()
idx <- 1
for(l1 in layer1){
  for(l2 in layer2){
    selectedIndices_nn <- nn_nout$pred$layer1 == l1 & nn$pred$layer2 == l2 & nn$pred$layer3 == 0
    plots[[idx]] <- ggplot(nn_nout$pred[selectedIndices_nn, ], aes(m = Yes,d=factor(obs, levels = c("Yes", "No")))) + 
      geom_roc(n.cuts=0) + 
      coord_equal() +
      style_roc()
    auc <- round(calc_auc(plots[[idx]]),4)
    print(auc[3])
    results[[idx]] = c(l1,l2,auc[3],idx)
    idx = idx + 1
  }
}
df_trans <-  as.data.frame(t(matrix(unlist(results), nrow=length(unlist(results[1])))))
colnames(df_trans) <- c("L1", "L2", "AUC", "idx")

#Best params: L1 = 10, l2=5, l3=0
#retrain nn w/ best params
layers <- expand.grid(layer1=c(10), layer2=c(5), layer3=c(0))
nn_opt <- train(as.factor(Malicious) ~., data = caret_data, method = "mlpML",
            trControl=control,
            preProcess = c("range"),
            metric = "ROC",
            tuneGrid=layers)
layers <- expand.grid(layer1=c(26,10), layer2=c(5,10,50), layer3=c(0))
nn_nout <- train(as.factor(Malicious) ~., data = cdata_nout, method = "mlpML",
                trControl=control,
                preProcess = c("range"),
                metric = "ROC",
                tuneGrid=layers)


selectedIndices_nn <- nn$pred$layer1 == 10 & nn$pred$layer2 == 5 & nn$pred$layer3 == 0
selectedIndices_nn_nout <- nn_nout$pred$layer1 == 10 & nn_nout$pred$layer2 == 5 & nn_nout$pred$layer3 == 0

k <- ggplot(nn$pred[selectedIndices_nn, ], aes(m = Yes,d=factor(obs, levels = c("Yes", "No")))) + 
  geom_roc(n.cuts=0) + 
  coord_equal() +
  style_roc()

k + annotate("text", y=0.25, x=0.75,label=paste("AUC =", round((calc_auc(k))$AUC, 4)))
auc <- round(calc_auc(k),4)

test_pred_nn <- predict(nn_opt, newdata = caret_test[,-1])
test_pred_nn_nout <- predict(nn_nout, newdata = caret_test[,-1])

confusionMatrix(test_pred_nn, as.factor(caret_test[,1]))
confusionMatrix(test_pred_nn_nout, as.factor(caret_test[,1]))


##################### Neural Network Results ##################### 
# Confusion Matrix and Statistics
# 
# Reference
# Prediction   No  Yes
# No  1855  128
# Yes  345 1546
# 
# Accuracy : 0.8779          
# 95% CI : (0.8672, 0.8881)
# No Information Rate : 0.5679          
# P-Value [Acc > NIR] : < 2.2e-16       
# 
# Kappa : 0.755           
# Mcnemar's Test P-Value : < 2.2e-16       
#                                           
#             Sensitivity : 0.8432          
#             Specificity : 0.9235          
#          Pos Pred Value : 0.9355          
#          Neg Pred Value : 0.8176          
#              Prevalence : 0.5679          
#          Detection Rate : 0.4788          
#    Detection Prevalence : 0.5119          
#       Balanced Accuracy : 0.8834          
#                                           
#        'Positive' Class : No
###################### Importance plots ###################
calc_auc(k)
#First run to check variable importance
set.seed(12)
rf1 <- randomForest(all_data[,-c(1:6, 32:35)], all_data[,1], mtry = 11, ntree = 300, importance = T)
rf_tr <- randomForest(caret_data[,-c(1, 27:31)], caret_data[,1], mtry = 11, ntree = 300, importance = T)
rf_tr_2 <- randomForest(caret_data[,-c(1, 27:31)], caret_data[,1], mtry = 2, ntree = 300, importance = T)

var_imp <- varImpPlot(rf1, sort = TRUE, main = "Variable Importance")

#Asthetic changes to importance plot
imp <- data.frame((rf1$importance)[,4])

imp <- imp %>% rownames_to_column(var="Variables") %>% remove_rownames
colnames(imp)[2] <-  "MeanGiniDecrease"
imp <- imp[order(-imp$MeanGiniDecrease),][1:25,]

plot3 <- ggplot(imp) + geom_point(aes(x = MeanGiniDecrease,y = reorder(Variables, MeanGiniDecrease)), size = 5, color = "sienna2")+
  ylab("Variables") + 
  theme(panel.background = element_rect(fill = 'grey93'),
        axis.text=element_text(size=12, face = "bold",color = "grey18"),
        axis.title=element_text(size=20,face="bold",color = "grey18"),
        plot.background = element_rect(fill = "grey93"))
#Get rf1 preds
test_pred_rf1 <- predict(rf1, newdata = caret_test[,-1])
confusionMatrix(test_pred_rf1, as.factor(caret_test[,1]))


###################### ROC plots ###################
rf_preds <- rf$pred[selectedIndices_rf, ]
svm_preds <- svm_Radial$pred[selectedIndices_svm, ]
nb_preds <- nb$pred[selectedIndices_nb, ]
lr_preds <- lr.df
nn_preds <- nn$pred[selectedIndices_nn,]

#Select only relevant columns
rf_no_preds <- rf_preds[, c(2,4,5)]
svm_no_preds <- svm_preds[, c(2,4,5)]
nb_no_preds <- nb_preds[, c(2,4,5)]
lr_no_preds <- lr_preds[, c(1,3,4)]
nn_no_preds <- nn_preds[, c(2,4,5)]

#Rename probablilites column to identify model
colnames(rf_no_preds)[2] <- "Random Forest"
colnames(svm_no_preds)[2] <- "Radial SVM"
colnames(nb_no_preds)[2] <- "Naive Bayes"
colnames(lr_no_preds)[1] <- "Logistic Regression"
colnames(nn_no_preds)[2] <- "Neural Net"


#Merge probabilities
all_preds <- Reduce(function(dtf1, dtf2) merge(dtf1, dtf2, by = c("obs", "rowIndex"), all = TRUE),list(rf_no_preds,svm_no_preds, nb_no_preds, lr_no_preds, nn_no_preds))
all_preds_sub <- all_preds[which(!is.na(all_preds$`Radial SVM`)),]
########### With Naive Bayes ###################
#Melt into longform for vizualization
longtest <- melt_roc(all_preds, "obs", c("Random Forest", "Radial SVM", "Naive Bayes", "Logistic Regression", "Neural Net"))

#Plot
combined_roc <- ggplot(longtest, aes(d = D, m = M, color = name )) + geom_roc(n.cuts = F, size = 1)
  
plot4 <- combined_roc+
          theme(axis.text=element_text(size=12,color = "grey18"),
              axis.title=element_text(size=20,color = "grey18"),
              legend.text = element_text(size=16),
              legend.title = element_text(size=18),
              plot.background = element_rect(fill = "white"), 
              panel.background = element_rect(fill = "grey97"),
              panel.grid.major = element_line(color="grey77"),
              panel.grid.minor = element_line(color="grey77"),
              )+
              labs(x="False Positive Rate", y="True Positive Rate", color="Model")

########### Without Naive Bayes ###################
#Melt into longform for vizualization
longtest <- melt_roc(all_preds, "obs", c("Random Forest", "Radial SVM", "Logistic Regression"))
#Plot
combined_roc <- ggplot(longtest, aes(d = D, m = M, color = name )) + geom_roc(n.cuts = F, size = 2)

plot4 <- combined_roc+ annotate("text", y=0.18, x=0.74,color = "grey93",size = 8,label=paste("LR AUC =", round((calc_auc(l))$AUC, 4)))+
  annotate("text", y=0.23, x=0.75,color = "grey93",size = 8,label=paste("SVM AUC =", round((calc_auc(g))$AUC, 4)))+
  annotate("text", y=0.28, x=0.74,color = "grey93",size = 8,label=paste("RF AUC =",round((calc_auc(h))$AUC, 4)))+
  theme(panel.background = element_rect(fill = 'grey18'),
        axis.text=element_text(size=12, face = "bold",color = "grey93"),
        axis.title=element_text(size=20,face="bold",color = "grey93"),
        plot.background = element_rect(fill = "grey18"))
  + geom_line(aes(c(0,0), c(1,1), colour=g1), d1) 

abline(a=0, b= 1)
plot4

grid.arrange(plot1, plot2, ncol=2)
